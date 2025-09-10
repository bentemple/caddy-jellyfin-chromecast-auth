package jellyfinauth

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// shouldAllowSecondary allows limited GETs without Authorization when IP is temp allowed
// This covers images and HLS requests with API keys
func (m *Middleware) shouldAllowSecondary(r *http.Request, ip net.IP) bool {
	if r.Method != http.MethodGet || !m.isTempAllowedIP(ip) {
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

// Temp Allowed IP memory management (used by preflights & secondary GETs)

// isTempAllowedIP checks if an IP address is currently marked as temp allowed
func (m *Middleware) isTempAllowedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	now := time.Now()
	m.mu.RLock()
	until, ok := m.tempAllowedIPs[ip.String()]
	m.mu.RUnlock()
	if !ok || now.After(until) {
		if ok {
			m.mu.Lock()
			delete(m.tempAllowedIPs, ip.String())
			m.mu.Unlock()
		}
		return false
	}
	return true
}

// markTempAllowedIP marks an IP address as temp allowed for the configured TTL
func (m *Middleware) markTempAllowedIP(ip net.IP) {
	if ip == nil {
		return
	}
	m.mu.Lock()
	m.tempAllowedIPs[ip.String()] = time.Now().Add(time.Duration(m.TempAllowedIPTTL))
	m.mu.Unlock()
}

// hasAPIKey checks if a request contains an API key parameter
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
