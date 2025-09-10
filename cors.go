package jellyfinauth

import (
	"net"
	"net/http"
	"strings"
)

// isCORSPreflight checks if a request is a CORS preflight request
func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

// preflightAllowed decides whether a CORS preflight request is "expected"
// This is kept tight to reduce service fingerprinting
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
	if m.RequireKnownIPForPreflight && !m.isTempAllowedIP(ip) {
		return false
	}

	return true
}
