package jellyfinauth

import (
	"bufio"
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// validateWithUpstream validates an authorization header against the upstream Jellyfin server
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

// Cache management functions

// isCached checks if an authorization header is cached and still valid
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

// setCache stores an authorization header in the cache with TTL
func (m *Middleware) setCache(key string) {
	m.mu.Lock()
	m.cache[key] = time.Now().Add(time.Duration(m.CacheTTL))
	m.mu.Unlock()
}

// Authorization header validation

// hasClient checks if an authorization header contains the required client name
func hasClient(auth, want string) bool {
	if strings.Contains(auth, `Client="`+want+`"`) {
		return true
	}
	return strings.Contains(auth, "Client="+want)
}

// sanitizeAuth cleans and validates an authorization header
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

// isSingleLine checks if a string contains only a single line
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