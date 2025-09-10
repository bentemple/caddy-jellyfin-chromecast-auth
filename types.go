package jellyfinauth

import (
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Middleware provides Jellyfin authentication for Chromecast integration
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
	// Log level (debug, info, warn, error) - default: info
	LogLevel string `json:"log_level,omitempty"`

	// Always-allow networks (skip checks, proxy)
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
	TempAllowedIPTTL           caddy.Duration `json:"temp_allowed_ip_ttl,omitempty"` // default: 15m

	// Secondary (non-auth) GETs (images/HLS) policy
	AllowedSecondaryUA      []string `json:"allowed_secondary_ua,omitempty"`
	AllowedSecondaryOrigins []string `json:"allowed_secondary_origins,omitempty"`

	// Upstream "OK" statuses (default: 200, 204, 206, 304)
	OKStatuses []int `json:"ok_statuses,omitempty"`

	// internals
	client         *http.Client
	proxy          *httputil.ReverseProxy
	mu             sync.RWMutex
	cache          map[string]time.Time // Authorization -> expiry
	allowedNets    []*net.IPNet
	failStats      map[string]failBucket // ip -> failures within window
	bans           map[string]time.Time  // ip -> banned until
	tempAllowedIPs map[string]time.Time  // ip -> temp allowed until
}

// failBucket tracks failure statistics for an IP within a time window
type failBucket struct {
	count int
	first time.Time
}

// ctxIPKey is used to store IP addresses in request context
type ctxIPKey struct{}

// Interface compliance checks
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
	_ caddy.Module                = (*Middleware)(nil)
)

// Regular expressions for matching request paths
var (
	reImagePath = regexp.MustCompile("(?i)^/items/[^/]+/images/")
	reHLSMaster = regexp.MustCompile("(?i)^/videos/[^/]+/master\\.m3u8$")
	reHLSPath   = regexp.MustCompile("(?i)^/videos/[^/]+/(hls/|live/)")
)
