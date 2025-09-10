package jellyfinauth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("jellyfinauth", parseJellyfinauthCaddyfile)
}

type Middleware struct {
	// Jellyfin base URL, e.g. http://jellyfin:8096 (scheme required)
	Upstream string `json:"upstream,omitempty"`
	// Auth-gated endpoint to validate tokens (default: /System/Info)
	Endpoint string `json:"endpoint,omitempty"`
	// Optional required Client name in Authorization header (e.g., Chromecast)
	RequireClient string `json:"require_client,omitempty"`
	// Cache TTL for valid Authorization headers (default: 10m)
	CacheTTL caddy.Duration `json:"cache_ttl,omitempty"`
	// Per-request validation timeout (default: 2s)
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// Always-allow networks (skip checks, mark warm, proxy)
	AllowCIDRs     []string `json:"allow_cidrs,omitempty"`
	TrustForwarded bool     `json:"trust_forwarded,omitempty"`

	// Fail-2-ban config
	FailBanThreshold int            `json:"failban_threshold,omitempty"` // default: 5
	FailBanWindow    caddy.Duration `json:"failban_window,omitempty"`    // default: 2m
	FailBanDuration  caddy.Duration `json:"failban_duration,omitempty"`  // default: 10m

	// Preflight policy
	AllowedOrigins             []string       `json:"allowed_origins,omitempty"`           // e.g. https://apps.jellyfin.org
	AllowedPreflightMethods    []string       `json:"allowed_preflight_methods,omitempty"` // e.g. GET POST
	AllowedPreflightUA         []string       `json:"allowed_preflight_ua,omitempty"`      // substrings/wildcards
	RequireKnownIPForPreflight bool           `json:"require_known_ip_for_preflight,omitempty"`
	WarmIPTTL                  caddy.Duration `json:"warm_ip_ttl,omitempty"` // default: 15m

	// Secondary (non-auth) GETs (images/HLS) policy
	AllowedSecondaryUA      []string `json:"allowed_secondary_ua,omitempty"`
	AllowedSecondaryOrigins []string `json:"allowed_secondary_origins,omitempty"`

	// Upstream “OK” statuses (default: 200, 204, 206, 304)
	OKStatuses []int `json:"ok_statuses,omitempty"`

	// internals
	client      *http.Client
	proxy       *httputil.ReverseProxy
	mu          sync.RWMutex
	cache       map[string]time.Time   // Authorization -> expiry
	allowedNets []*net.IPNet
	failStats   map[string]failBucket  // ip -> failures within window
	bans        map[string]time.Time   // ip -> banned until
	warmIP      map[string]time.Time   // ip -> warm until
}

type failBucket struct {
	count int
	first time.Time
}

type ctxIPKey struct{}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddy.Module                = (*Middleware)(nil)

	reImagePath = regexp.MustCompile(`(?i)^/items/[^/]+/images/`)
	reHLSMaster = regexp.MustCompile(`(?i)^/videos/[^/]+/master\.m3u8$`)
	reHLSPath   = regexp.MustCompile(`(?i)^/videos/[^/]+/(hls/|live/)`)
)

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jellyfinauth",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func parseJellyfinauthCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

// --- Provision/Validate ---

func (m *Middleware) Provision(ctx caddy.Context) error {
	if m.Endpoint == "" {
		m.Endpoint = "/System/Info"
	}
	if m.Timeout == 0 {
		m.Timeout = caddy.Duration(2 * time.Second)
	}
	if m.CacheTTL == 0 {
		m.CacheTTL = caddy.Duration(10 * time.Minute)
	}
	if m.FailBanThreshold <= 0 {
		m.FailBanThreshold = 5
	}
	if m.FailBanWindow == 0 {
		m.FailBanWindow = caddy.Duration(2 * time.Minute)
	}
	if m.FailBanDuration == 0 {
		m.FailBanDuration = caddy.Duration(10 * time.Minute)
	}
	if m.WarmIPTTL == 0 {
		m.WarmIPTTL = caddy.Duration(15 * time.Minute)
	}
	if len(m.AllowedPreflightMethods) == 0 {
		m.AllowedPreflightMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	}
	if len(m.AllowedOrigins) == 0 {
		m.AllowedOrigins = []string{"https://apps.jellyfin.org"}
	}
	if len(m.AllowedPreflightUA) == 0 {
		m.AllowedPreflightUA = []string{"CrKey/", "Chromecast", "Jellyfin"}
	}
	// inherit to secondary if unset
	if len(m.AllowedSecondaryUA) == 0 {
		m.AllowedSecondaryUA = append([]string(nil), m.AllowedPreflightUA...)
	}
	if len(m.AllowedSecondaryOrigins) == 0 {
		m.AllowedSecondaryOrigins = append([]string(nil), m.AllowedOrigins...)
	}
	if len(m.OKStatuses) == 0 {
		m.OKStatuses = []int{http.StatusOK, http.StatusNoContent, http.StatusPartialContent, http.StatusNotModified} // 200,204,206,304
	}

	m.client = http.DefaultClient
	m.cache = make(map[string]time.Time)
	m.failStats = make(map[string]failBucket)
	m.bans = make(map[string]time.Time)
	m.warmIP = make(map[string]time.Time)

	for _, cidr := range m.AllowCIDRs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return fmt.Errorf("jellyfinauth: bad allow_cidr %q: %v", cidr, err)
		}
		m.allowedNets = append(m.allowedNets, n)
	}

	up, err := url.Parse(m.Upstream)
	if err != nil {
		return fmt.Errorf("invalid upstream: %v", err)
	}
	rp := httputil.NewSingleHostReverseProxy(up)

	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origHost := req.Host
		origDirector(req)      // set scheme/host to upstream
		req.Host = origHost    // preserve incoming Host for Jellyfin
		if req.Header.Get("X-Forwarded-Proto") == "" {
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		}
	}
	rp.FlushInterval = -1
	var errUpstreamNonOK = errors.New("upstream returned non-OK")
	rp.ModifyResponse = func(resp *http.Response) error {
		ipStr, _ := resp.Request.Context().Value(ctxIPKey{}).(string)
		ip := net.ParseIP(ipStr)

		ok := false
		for _, s := range m.OKStatuses {
			if resp.StatusCode == s {
				ok = true
				break
			}
		}
		if ok {
			m.clearFailures(ip)
			m.markWarmIP(ip)
			return nil
		}
		// Non-OK -> count a failure; ErrorHandler sends 418
		m.noteFailure(ip)
		return errUpstreamNonOK
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		_ = teapot(w, r)
	}
	rp.Transport = http.DefaultTransport
	m.proxy = rp

	return nil
}

func (m *Middleware) Validate() error {
	if m.Upstream == "" {
		return errors.New("jellyfinauth: upstream is required (e.g. http://jellyfin:8096)")
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

// --- Serve ---

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := m.clientIP(r)

	// True CORS preflight? Only allow if "expected"
	if isCORSPreflight(r) {
		if m.preflightAllowed(r, ip) {
			ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
			m.proxy.ServeHTTP(w, r.WithContext(ctx))
			return nil
		}
		return teapot(w, r)
	}

	// Ban check
	if m.isBanned(ip) {
		return teapot(w, r)
	}

	// Allowlist -> proxy and mark warm
	if m.ipAllowed(ip) {
		m.markWarmIP(ip)
		ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
		m.proxy.ServeHTTP(w, r.WithContext(ctx))
		return nil
	}

	// Warm secondary GETs (images, HLS with api_key) -> proxy
	if m.allowWarmSecondary(r, ip) {
		ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
		m.proxy.ServeHTTP(w, r.WithContext(ctx))
		return nil
	}

	// Require Authorization: MediaBrowser ...
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.Contains(auth, "MediaBrowser") {
		m.noteFailure(ip)
		return teapot(w, r)
	}
	if m.RequireClient != "" && !hasClient(auth, m.RequireClient) {
		m.noteFailure(ip)
		return teapot(w, r)
	}

	// Sanitize and possibly normalize whitespace
	clean, ok := sanitizeAuth(auth)
	if !ok {
		m.noteFailure(ip)
		return teapot(w, r)
	}

	// Cache hit -> proxy
	if m.isCached(clean) {
		m.clearFailures(ip)
		m.markWarmIP(ip)
		ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
		r.Header.Set("Authorization", clean)
		m.proxy.ServeHTTP(w, r.WithContext(ctx))
		return nil
	}

	// Online validation (per-request ctx timeout)
	ok, err := m.validateWithUpstream(r.Context(), clean)
	if err != nil || !ok {
		m.noteFailure(ip)
		return teapot(w, r)
	}

	// Cache + proxy
	m.setCache(clean)
	m.clearFailures(ip)
	m.markWarmIP(ip)
	ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
	r.Header.Set("Authorization", clean)
	m.proxy.ServeHTTP(w, r.WithContext(ctx))
	return nil
}

// --- Helpers ---

func teapot(w http.ResponseWriter, r *http.Request) error {
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusTeapot)
	return nil
}

func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

// Decide whether a preflight is "expected" (tight to reduce service fingerprinting)
func (m *Middleware) preflightAllowed(r *http.Request, ip net.IP) bool {
	// Must be preflight for Authorization
	if !strings.Contains(strings.ToLower(r.Header.Get("Access-Control-Request-Headers")), "authorization") {
		return false
	}
	// Allowed Origin
	if len(m.AllowedOrigins) > 0 && !matchOneCI(r.Header.Get("Origin"), m.AllowedOrigins) {
		return false
	}
	// Allowed method
	if len(m.AllowedPreflightMethods) > 0 && !containsCI(m.AllowedPreflightMethods, r.Header.Get("Access-Control-Request-Method")) {
		return false
	}
	// Allowed UA hint
	if len(m.AllowedPreflightUA) > 0 && !matchOneCI(r.Header.Get("User-Agent"), m.AllowedPreflightUA) {
		return false
	}
	// Require recent validated request from this IP?
	if m.RequireKnownIPForPreflight && !m.isWarmIP(ip) {
		return false
	}
	return true
}

// Allow limited GETs without Authorization when IP is warm (images, HLS with api_key)
func (m *Middleware) allowWarmSecondary(r *http.Request, ip net.IP) bool {
	if r.Method != http.MethodGet || !m.isWarmIP(ip) {
		return false
	}

	// UA must match allowed secondary UA list
	if len(m.AllowedSecondaryUA) > 0 && !matchOneCI(r.Header.Get("User-Agent"), m.AllowedSecondaryUA) {
		return false
	}

	// Origin/Referer must match allowed secondary origins (if any)
	origin := r.Header.Get("Origin")
	if origin != "" {
		if len(m.AllowedSecondaryOrigins) > 0 && !matchOneCI(origin, m.AllowedSecondaryOrigins) {
			return false
		}
	} else {
		if len(m.AllowedSecondaryOrigins) > 0 && !matchOneCI(r.Header.Get("Referer"), m.AllowedSecondaryOrigins) {
			return false
		}
	}

	p := strings.ToLower(r.URL.Path)
	if reImagePath.MatchString(p) {
		return true
	}
	if reHLSMaster.MatchString(p) || reHLSPath.MatchString(p) {
		return hasAPIKey(r)
	}
	return false
}

// Warm-IP memory (used by preflights & secondary GETs)
func (m *Middleware) isWarmIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	now := time.Now()
	m.mu.RLock()
	until, ok := m.warmIP[ip.String()]
	m.mu.RUnlock()
	if !ok || now.After(until) {
		if ok {
			m.mu.Lock()
			delete(m.warmIP, ip.String())
			m.mu.Unlock()
		}
		return false
	}
	return true
}

func (m *Middleware) markWarmIP(ip net.IP) {
	if ip == nil {
		return
	}
	m.mu.Lock()
	m.warmIP[ip.String()] = time.Now().Add(time.Duration(m.WarmIPTTL))
	m.mu.Unlock()
}

func hasAPIKey(r *http.Request) bool {
	q := r.URL.Query()
	if v := q.Get("api_key"); v != "" {
		return true
	}
	if v := q.Get("ApiKey"); v != "" {
		return true
	}
	return false
}

func (m *Middleware) validateWithUpstream(ctx context.Context, authHeader string) (bool, error) {
	base, _ := url.Parse(m.Upstream)
	ep, _ := url.Parse(m.Endpoint)
	u := base.ResolveReference(ep)

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

// --- Cache (Authorization) ---

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

// --- Fail-2-ban ---

func (m *Middleware) noteFailure(ip net.IP) {
	if ip == nil {
		return
	}
	key := ip.String()
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	if until, banned := m.bans[key]; banned && now.Before(until) {
		return
	}

	b := m.failStats[key]
	window := time.Duration(m.FailBanWindow)
	if b.first.IsZero() || now.Sub(b.first) > window {
		b = failBucket{count: 0, first: now}
	}
	b.count++
	m.failStats[key] = b

	if b.count >= m.FailBanThreshold {
		m.bans[key] = now.Add(time.Duration(m.FailBanDuration))
		delete(m.failStats, key)
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
		m.mu.Lock()
		delete(m.bans, key)
		m.mu.Unlock()
		return false
	}
	return true
}

// --- Misc utils ---

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
	if strings.ContainsAny(v, "\r\n") {
		return "", false
	}
	v = strings.TrimSpace(v)

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

func matchOneCI(s string, patterns []string) bool {
	ls := strings.ToLower(s)
	for _, p := range patterns {
		lp := strings.ToLower(p)
		switch {
		case lp == "*":
			return true
		case strings.HasPrefix(lp, "*") && strings.HasSuffix(lp, "*"):
			needle := strings.Trim(lp, "*")
			if needle == "" || strings.Contains(ls, needle) {
				return true
			}
		case strings.HasPrefix(lp, "*"):
			if strings.HasSuffix(ls, strings.TrimPrefix(lp, "*")) {
				return true
			}
		case strings.HasSuffix(lp, "*"):
			if strings.HasPrefix(ls, strings.TrimSuffix(lp, "*")) {
				return true
			}
		default:
			if ls == lp {
				return true
			}
		}
	}
	return false
}

func containsCI(list []string, val string) bool {
	v := strings.ToLower(val)
	for _, s := range list {
		if strings.ToLower(s) == v {
			return true
		}
	}
	return false
}

// --- Caddyfile parsing ---

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
			case "allow_origin":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.AllowedOrigins = append(m.AllowedOrigins, args...)
			case "allow_preflight_method":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.AllowedPreflightMethods = append(m.AllowedPreflightMethods, args...)
			case "allow_preflight_ua":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.AllowedPreflightUA = append(m.AllowedPreflightUA, args...)
			case "preflight_require_known_ip":
				m.RequireKnownIPForPreflight = true
			case "warm_ip_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid warm_ip_ttl: %v", err)
				}
				m.WarmIPTTL = caddy.Duration(dur)
			case "allow_secondary_ua":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.AllowedSecondaryUA = append(m.AllowedSecondaryUA, args...)
			case "allow_secondary_origin":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.AllowedSecondaryOrigins = append(m.AllowedSecondaryOrigins, args...)
			case "ok_status":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				for _, a := range args {
					var v int
					if _, err := fmt.Sscanf(a, "%d", &v); err != nil || v < 100 || v > 599 {
						return d.Errf("invalid ok_status: %q", a)
					}
					m.OKStatuses = append(m.OKStatuses, v)
				}
			default:
				return d.Errf("unrecognized subdirective %q", d.Val())
			}
		}
	}
	return nil
}

