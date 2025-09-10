package jellyfinauth

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// teapot sends an HTTP 418 "I'm a teapot" response to reduce service fingerprinting
func teapot(w http.ResponseWriter, r *http.Request) error {
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusTeapot)
	return nil
}

// clientIP extracts the client IP address from a request
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

// isIPAlwaysAllowed checks if an IP address is in the allowed networks list
func (m *Middleware) isIPAlwaysAllowed(ip net.IP) bool {
	if ip == nil {
		slog.Debug("jellyfinauth: IP is nil")
		return false
	}
	slog.Debug("jellyfinauth: checking IP against allowlist", "ip", ip.String(), "allowed_nets_count", len(m.allowedNets))
	for i, n := range m.allowedNets {
		slog.Debug("jellyfinauth: checking against network", "ip", ip.String(), "network", n.String(), "index", i)
		if n.Contains(ip) {
			slog.Debug("jellyfinauth: IP matches network", "ip", ip.String(), "network", n.String())
			return true
		}
	}
	slog.Debug("jellyfinauth: IP does not match any allowed networks", "ip", ip.String())
	return false
}

// String matching utilities

// matchOneCI performs case-insensitive pattern matching with wildcard support
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

// containsCI checks if a list contains a value (case-insensitive)
func containsCI(list []string, val string) bool {
	v := strings.ToLower(val)
	for _, s := range list {
		if strings.ToLower(s) == v {
			return true
		}
	}
	return false
}
