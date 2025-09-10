package jellyfinauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// Provision sets up the middleware with default values and initializes internal components
func (m *Middleware) Provision(ctx caddy.Context) error {
	// Set log level
	if m.LogLevel == "" {
		m.LogLevel = "info"
	}
	var level slog.Level
	switch strings.ToLower(m.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		return fmt.Errorf("invalid log_level %q, must be: debug, info, warn, error", m.LogLevel)
	}
	slog.SetLogLoggerLevel(level)

	// Set default values
	if err := m.setDefaults(); err != nil {
		return err
	}

	// Initialize internal maps
	m.initializeMaps()

	// Parse allowed CIDR ranges
	if err := m.parseAllowedNets(); err != nil {
		return err
	}

	// Set up reverse proxy
	if err := m.setupReverseProxy(); err != nil {
		return err
	}

	return nil
}

// Validate ensures the middleware configuration is valid
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

// setDefaults initializes default configuration values
func (m *Middleware) setDefaults() error {
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
	if m.TempAllowedIPTTL == 0 {
		m.TempAllowedIPTTL = caddy.Duration(15 * time.Minute)
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

	return nil
}

// initializeMaps creates internal data structures
func (m *Middleware) initializeMaps() {
	m.client = http.DefaultClient
	m.cache = make(map[string]time.Time)
	m.failStats = make(map[string]failBucket)
	m.bans = make(map[string]time.Time)
	m.tempAllowedIPs = make(map[string]time.Time)
}

// parseAllowedNets converts CIDR strings to network objects
func (m *Middleware) parseAllowedNets() error {
	for _, cidr := range m.AllowCIDRs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return fmt.Errorf("jellyfinauth: bad allow_cidr %q: %v", cidr, err)
		}
		m.allowedNets = append(m.allowedNets, n)
	}
	return nil
}

// setupReverseProxy configures the internal reverse proxy
func (m *Middleware) setupReverseProxy() error {
	up, err := url.Parse(m.Upstream)
	if err != nil {
		return fmt.Errorf("invalid upstream: %v", err)
	}

	rp := httputil.NewSingleHostReverseProxy(up)

	// Customize the Director to handle Host headers properly
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origHost := req.Host
		origPath := req.URL.Path
		origDirector(req) // set scheme/host to upstream

		req.Host = up.Host
		// Set proper headers for upstream
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", origHost)
		}
		if req.Header.Get("X-Forwarded-Proto") == "" {
			if req.TLS != nil {
				req.Header.Set("X-Forwarded-Proto", "https")
			} else {
				req.Header.Set("X-Forwarded-Proto", "http")
			}
		}

		slog.Debug("jellyfinauth: proxying request",
			"original_host", origHost,
			"original_path", origPath,
			"target_url", req.URL.String(),
			"target_host", req.Host,
			"upstream_host", up.Host,
			"target_path", req.URL.Path,
			"method", req.Method)
	}

	rp.FlushInterval = -1
	errUpstreamNonOK := errors.New("upstream returned non-OK")

	// Handle response status codes for fail2ban
	rp.ModifyResponse = func(resp *http.Response) error {
		ipStr, _ := resp.Request.Context().Value(ctxIPKey{}).(string)
		ip := net.ParseIP(ipStr)

		// OK if no OKStatuses defined and >=100 && <400
		ok := len(m.OKStatuses) == 0 &&
			resp.StatusCode >= http.StatusContinue &&
			resp.StatusCode < http.StatusBadRequest

		if !ok {
			// Otherwise, verify that it is an acceptable response status.
			for _, s := range m.OKStatuses {
				if resp.StatusCode == s {
					ok = true
					break
				}
			}
		}
		if ok {
			slog.Debug("jellyfinauth: upstream response OK", "status_code", resp.StatusCode, "url", resp.Request.URL.String())
			m.clearFailures(ip)
			m.markTempAllowedIP(ip)
			return nil
		}
		// Non-OK -> count a failure; ErrorHandler sends 418
		slog.Debug("jellyfinauth: upstream response not OK", "status_code", resp.StatusCode, "url", resp.Request.URL.String(), "ok_statuses", m.OKStatuses)
		m.recordFailure(ip)
		return errUpstreamNonOK
	}

	// Handle proxy errors
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("jellyfinauth: proxy error",
			"error", err.Error(),
			"target_url", r.URL.String(),
			"method", r.Method,
			"path", r.URL.Path,
			"upstream", m.Upstream)
		_ = teapot(w, r)
	}

	rp.Transport = http.DefaultTransport
	m.proxy = rp

	return nil
}
