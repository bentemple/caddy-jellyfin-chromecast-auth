package jellyfin_auth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Middleware{})
}

type Middleware struct {
	Upstream       string         `json:"upstream,omitempty"`
	Endpoint       string         `json:"endpoint,omitempty"`        // default /System/Info
	RequireClient  string         `json:"require_client,omitempty"`  // e.g. Chromecast
	CacheTTL       caddy.Duration `json:"cache_ttl,omitempty"`       // default 10m
	Timeout        caddy.Duration `json:"timeout,omitempty"`         // per-request ctx timeout; default 2s

	// Always-allow networks (skip checks)
	AllowCIDRs     []string `json:"allow_cidrs,omitempty"`
	TrustForwarded bool     `json:"trust_forwarded,omitempty"`

	// Fail-2-ban
	FailBanThreshold int            `json:"failban_threshold,omitempty"` // e.g. 5 failures
	FailBanWindow    caddy.Duration `json:"failban_window,omitempty"`    // e.g. 2m window
	FailBanDuration  caddy.Duration `json:"failban_duration,omitempty"`  // e.g. 10m ban

	client *http.Client

	mu          sync.RWMutex
	cache       map[string]time.Time   // Authorization header -> expiry
	allowedNets []*net.IPNet
	failStats   map[string]failBucket  // ip -> rolling failures
	bans        map[string]time.Time   // ip -> banned until
}

type failBucket struct {
	count int
	first time.Time
}

var _ caddy.Provisioner = (*Middleware)(nil)
var _ caddy.Validator = (*Middleware)(nil)
var _ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
var _ caddyfile.Unmarshaler = (*Middleware)(nil)

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jellyfinauth",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m *Middleware) Provision(caddy.Context) error {
	if m.Endpoint == "" {
		m.Endpoint = "/System/Info"
	}
	if m.Timeout == 0 {
		m.Timeout = caddy.Duration(2 * time.Second)
	}
	if m.CacheTTL == 0 {
		m.CacheTTL = caddy.Duration(10 * time.Minute)
	}
	// Sensible fail2ban defaults if not provided
	if m.FailBanThreshold <= 0 {
		m.FailBanThreshold = 5
	}
	if m.FailBanWindow == 0 {
		m.FailBanWindow = caddy.Duration(2 * time.Minute)
	}
	if m.FailBanDuration == 0 {
		m.FailBanDuration = caddy.Duration(10 * time.Minute)
	}

	// Use the global default client; apply per-request ctx timeouts instead of hard-coding transport/timeouts.
	m.client = http.DefaultClient

	m.cache = make(map[string]time.Time)
	m.failStats = make(map[string]failBucket)
	m.bans = make(map[string]time.Time)

	for _, cidr := range m.AllowCIDRs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return fmt.Errorf("jellyfinauth: bad allow_cidr %q: %v", cidr, err)
		}
		m.allowedNets = append(m.allowedNets, n)
	}
	return nil
}

func (m *Middleware) Validate() error {
	if m.Upstream == "" {
		return errors.New("jellyfinauth: upstream is required (e.g. http://localhost:8096)")
	}
	u, err := url.Parse(m.Upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("jellyfinauth: invalid upstream: %q", m.Upstream)
	}
	if !strings.HasPrefix(m.Endpoint, "/") {
		return fmt.Errorf("jellyfinauth: endpoint must start with '/': %q", m.Endpoint)
	}
	return nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := m.clientIP(r)

	// 0) If IP is banned -> teapot
	if m.isBanned(ip) {
		return teapot(w, r)
	}

	// 1) Allowlist bypass
	if m.ipAllowed(ip) {
		return next.ServeHTTP(w, r)
	}

	// 2) Require MediaBrowser Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.Contains(auth, "MediaBrowser") {
		m.noteFailure(ip)
		return teapot(w, r)
	}

	// 3) Require specific Client (e.g., Chromecast)
	if m.RequireClient != "" && !hasClient(auth, m.RequireClient) {
		m.noteFailure(ip)
		return teapot(w, r)
	}

	// 4) Sanitize header value
	clean, ok := sanitizeAuth(auth)
	if !ok {
		m.noteFailure(ip)
		return teapot(w, r)
	}

	// 5) Cache hit
	if m.isCached(clean) {
		m.clearFailures(ip)
		return next.ServeHTTP(w, r)
	}

	// 6) Validate with upstream (per-request timeout)
	ok, err := m.validateWithUpstream(r.Context(), clean)
	if err != nil || !ok {
		m.noteFailure(ip)
		return teapot(w, r)
	}

	// 7) Cache and allow
	m.setCache(clean)
	m.clearFailures(ip)
	return next.ServeHTTP(w, r)
}

func teapot(w http.ResponseWriter, r *http.Request) error {
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusTeapot)
	return nil
}

func (m *Middleware) validateWithUpstream(ctx context.Context, authHeader string) (bool, error) {
	base, _ := url.Parse(m.Upstream)
	ep, _ := url.Parse(m.Endpoint)
	u := base.ResolveReference(ep)

	// Per-request timeout via context, not client-level timeout.
	if m.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(m.Timeout))
		defer cancel()
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", authHeader)

	resp, err := m.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// ----- Cache (Authorization) -----

func (m *Middleware) isCached(key string) bool {
	now := time.Now()
	m.mu.RLock()
	exp, ok := m.cache[key]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	if now.After(exp) {
		m.mu.Lock()
		delete(m.cache, key)
		m.mu.Unlock()
		return false
	}
	return true
}

func (m *Middleware) setCache(key string) {
	m.mu.Lock()
	m.cache[key] = time.Now().Add(time.Duration(m.CacheTTL))
	m.mu.Unlock()
}

// ----- Fail-2-ban -----

func (m *Middleware) noteFailure(ip net.IP) {
	if ip == nil {
		return
	}
	key := ip.String()
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	// If already banned, extend? Typically no — keep existing expiry.
	if until, banned := m.bans[key]; banned && now.Before(until) {
		return
	}

	b := m.failStats[key]
	// Reset if outside window
	window := time.Duration(m.FailBanWindow)
	if b.first.IsZero() || now.Sub(b.first) > window {
		b = failBucket{count: 0, first: now}
	}
	b.count++
	m.failStats[key] = b

	if b.count >= m.FailBanThreshold {
		m.bans[key] = now.Add(time.Duration(m.FailBanDuration))
		delete(m.failStats, key) // reset counter after ban
	}
}

func (m *Middleware) clearFailures(ip net.IP) {
	if ip == nil {
		return
	}
	m.mu.Lock()
	delete(m.failStats, ip.String())
	m.mu.Unlock()
}

func (m *Middleware) isBanned(ip net.IP) bool {
	if ip == nil {
		return false
	}
	now := time.Now()
	key := ip.String()

	m.mu.RLock()
	until, ok := m.bans[key]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	if now.After(until) {
		// Expired; clean up
		m.mu.Lock()
		delete(m.bans, key)
		m.mu.Unlock()
		return false
	}
	return true
}

// ----- Utils -----

func hasClient(auth, want string) bool {
	if strings.Contains(auth, `Client="`+want+`"`) {
		return true
	}
	return strings.Contains(auth, "Client="+want)
}

func sanitizeAuth(v string) (string, bool) {
	if len(v) == 0 || len(v) > 8192 {
		return "", false
	}
	// forbid CR/LF and obs-fold
	if strings.ContainsAny(v, "\r\n") {
		return "", false
	}
	v = strings.TrimSpace(v)

	// defense-in-depth: block traversal-ish or encoded control sequences
	lc := strings.ToLower(v)
	badSeq := []string{
		"../", `..\`, "%2e%2e%2f", "%2e%2e/", "/%2e%2e", "%2f%2e%2e",
		"%5c", "%0a", "%0d",
	}
	for _, b := range badSeq {
		if strings.Contains(lc, b) {
			return "", false
		}
	}

	if !strings.Contains(v, "MediaBrowser") {
		return "", false
	}

	spaceRe := regexp.MustCompile(`\s+`)
	v = spaceRe.ReplaceAllString(v, " ")

	if !isSingleLine(v) {
		return "", false
	}
	return v, true
}

func isSingleLine(s string) bool {
	sc := bufio.NewScanner(strings.NewReader(s))
	lineCount := 0
	for sc.Scan() {
		lineCount++
		if lineCount > 1 {
			return false
		}
	}
	return true
}

func (m *Middleware) clientIP(r *http.Request) net.IP {
	if m.TrustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
				return ip
			}
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			if ip := net.ParseIP(strings.TrimSpace(xr)); ip != nil {
				return ip
			}
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return net.ParseIP(host)
}

func (m *Middleware) ipAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range m.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ---- Caddyfile parsing ----

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "upstream":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Upstream = d.Val()
			case "endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Endpoint = d.Val()
			case "require_client":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RequireClient = d.Val()
			case "cache_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid cache_ttl: %v", err)
				}
				m.CacheTTL = caddy.Duration(dur)
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid timeout: %v", err)
				}
				m.Timeout = caddy.Duration(dur)
			case "allow_cidr":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.AllowCIDRs = append(m.AllowCIDRs, args...)
			case "trust_forwarded":
				m.TrustForwarded = true
			case "failban_threshold":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var v int
				if _, err := fmt.Sscanf(d.Val(), "%d", &v); err != nil || v <= 0 {
					return d.Errf("invalid failban_threshold: %q", d.Val())
				}
				m.FailBanThreshold = v
			case "failban_window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid failban_window: %v", err)
				}
				m.FailBanWindow = caddy.Duration(dur)
			case "failban_duration":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid failban_duration: %v", err)
				}
				m.FailBanDuration = caddy.Duration(dur)
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}
	return nil
}
