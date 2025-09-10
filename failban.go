package jellyfinauth

import (
	"net"
	"time"
)

// recordFailure records a failed authentication attempt for an IP address
func (m *Middleware) recordFailure(ip net.IP) {
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

// clearFailures removes all failure records for an IP address
func (m *Middleware) clearFailures(ip net.IP) {
	if ip == nil {
		return
	}
	m.mu.Lock()
	delete(m.failStats, ip.String())
	m.mu.Unlock()
}

// isBanned checks if an IP address is currently banned
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
