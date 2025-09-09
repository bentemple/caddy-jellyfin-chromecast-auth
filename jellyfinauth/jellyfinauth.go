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
	Upstream       string          `json:"upstream,omitempty"`
	Endpoint       string          `json:"endpoint,omitempty"`        // default /System/Info
	RequireClient  string          `json:"require_client,omitempty"`  // e.g. Chromecast
	CacheTTL       caddy.Duration  `json:"cache_ttl,omitempty"`       // default 10m
	Timeout        caddy.Duration  `json:"timeout,omitempty"`         // default 2s
	AllowCIDRs     []string        `json:"allow_cidrs,omitempty"`     // CIDR allowlist
	TrustForwarded bool            `json:"trust_forwarded,omitempty"` // honor XFF/X-Real-IP

	client      *http.Client
	mu          sync.RWMutex
	cache       map[string]time.Time
	allowedNets []*net.IPNet
}

var _ caddy.Provisioner = (*Middleware)(nil)
var _ caddy.Validator = (*Middleware)(nil)
var _ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
var _ caddyfile.Unmarshaler = (*Middleware)(nil)

func (m *Middleware) CaddyModule() caddy.ModuleInfo {
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
	m.client = &http.Client{
		Timeout: time.Duration(m.Timeout),
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   1 * time.Second,
				KeepAlive: 15 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   1 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	m.cache = make(map[string]time.Time)

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
	// 0) IP allowlist: immediate pass-through if matched
	if m.ipAllowed(m.clientIP(r)) {
		return next.ServeHTTP(w, r)
	}

	// 1) Require MediaBrowser Authorization header
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.Contains(auth, "MediaBrowser") {
		return teapot(w)
	}

	// 2) Require specific Client (e.g., Chromecast)
	if m.RequireClient != "" && !hasClient(auth, m.RequireClient) {
		return teapot(w)
	}

	// 3) Sanitize header value
	clean, ok := sanitizeAuth(auth)
	if !ok {
		return teapot(w)
	}

	// 4) Cache hit
	if m.isCached(clean) {
		return next.ServeHTTP(w, r)
	}

	// 5) Validate with upstream
	ok, err := m.validateWithUpstream(r.Context(), clean)
	if err != nil || !ok {
		return teapot(w)
	}

	// 6) Cache and allow
	m.setCache(clean)
	return next.ServeHTTP(w, r)
}

func teapot(w http.ResponseWriter) error {
	w.Header().Set("Connection", "close")
	http.Error(w, "I'm a teapot", http.StatusTeapot)
	return nil
}

func (m *Middleware) validateWithUpstream(ctx context.Context, authHeader string) (bool, error) {
	base, _ := url.Parse(m.Upstream)
	ep, _ := url.Parse(m.Endpoint)
	u := base.ResolveReference(ep)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("Authorization", authHeader)

	resp, err := m.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

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

func hasClient(auth, want string) bool {
	// tolerate either Client="Chromecast" or Client=Chromecast
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
				m.Upstream = d.Arg()
			case "endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Endpoint = d.Arg()
			case "require_client":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.RequireClient = d.Arg()
			case "cache_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Arg())
				if err != nil {
					return d.Errf("invalid cache_ttl: %v", err)
				}
				m.CacheTTL = caddy.Duration(dur)
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Arg())
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
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}
	return nil
}
