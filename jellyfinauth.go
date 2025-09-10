// Package jellyfinauth provides a Caddy HTTP middleware for Jellyfin authentication
// specifically designed for Chromecast integration with advanced security features.
package jellyfinauth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("jellyfinauth", parseJellyfinauthCaddyfile)
}

// CaddyModule returns the Caddy module information
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jellyfinauth",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// ServeHTTP implements the main authentication flow
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := m.clientIP(r)

	slog.Debug("jellyfinauth: processing request",
		"detected_ip", ip.String(),
		"remote_addr", r.RemoteAddr,
		"x_forwarded_for", r.Header.Get("X-Forwarded-For"),
		"x_real_ip", r.Header.Get("X-Real-IP"),
		"trust_forwarded", m.TrustForwarded,
		"path", r.URL.Path,
		"method", r.Method)

	// Allowlist -> proxy and mark temp-allowed
	if m.ipAllowed(ip) {
		slog.Debug("jellyfinauth: IP allowed, proxying", "ip", ip.String())
		ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
		m.proxy.ServeHTTP(w, r.WithContext(ctx))
		return nil
	}

	slog.Debug("jellyfinauth: IP not in allowlist, continuing auth flow", "ip", ip.String())

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

	// Temp Allowed IP secondary GETs (images, HLS with api_key) -> proxy
	if m.shouldAllowSecondary(r, ip) {
		ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
		m.proxy.ServeHTTP(w, r.WithContext(ctx))
		return nil
	}

	// Require Authorization: MediaBrowser ...
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.Contains(auth, "MediaBrowser") {
		m.recordFailure(ip)
		return teapot(w, r)
	}
	if m.RequireClient != "" && !hasClient(auth, m.RequireClient) {
		m.recordFailure(ip)
		return teapot(w, r)
	}

	// Sanitize and possibly normalize whitespace
	clean, ok := sanitizeAuth(auth)
	if !ok {
		m.recordFailure(ip)
		return teapot(w, r)
	}

	// Cache hit -> proxy
	if m.isCached(clean) {
		m.clearFailures(ip)
		m.markTempAllowedIP(ip)
		ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
		r.Header.Set("Authorization", clean)
		m.proxy.ServeHTTP(w, r.WithContext(ctx))
		return nil
	}

	// Online validation (per-request ctx timeout)
	ok, err := m.validateWithUpstream(r.Context(), clean)
	if err != nil || !ok {
		m.recordFailure(ip)
		return teapot(w, r)
	}

	// Cache + proxy
	m.setCache(clean)
	m.clearFailures(ip)
	m.markTempAllowedIP(ip)
	ctx := context.WithValue(r.Context(), ctxIPKey{}, ip.String())
	r.Header.Set("Authorization", clean)
	m.proxy.ServeHTTP(w, r.WithContext(ctx))
	return nil
}
