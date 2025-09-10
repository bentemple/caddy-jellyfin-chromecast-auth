package jellyfinauth

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// parseJellyfinauthCaddyfile creates a new Middleware instance from Caddyfile configuration
func parseJellyfinauthCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

// UnmarshalCaddyfile parses the Caddyfile configuration for jellyfinauth
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

			case "log_level":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.LogLevel = d.Val()

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

			case "temp_allowed_ip_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid temp_allowed_ip_ttl: %v", err)
				}
				m.TempAllowedIPTTL = caddy.Duration(dur)

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
