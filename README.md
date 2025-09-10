# caddy-jellyfinauth

CONTAINS AI GENERATED CODE.

## Why
My goal with this middleware is to allow chromecast requests that are outside of the VPN to succeed and function after passing an http request with a valid authorization header. Until that authorization header has successfully been used to connect to Jellyfin, all requests should respond as if jellyfin is not a running service (assuming `preflight_require_known_ip` is set).

## Features

A Caddy HTTP middleware that functions as a reverse proxy with the following additional features:
- Allows IP allowlist bypassing (CIDR ranges)
- Requires `Authorization: MediaBrowser ...` headers with `Client="Chromecast"`
- Validates tokens against Jellyfin's API
- Implements in-memory caching with TTL
- Includes fail2ban-style protection
- Supports CORS preflight handling
- Allows secondary requests (images/HLS) from temp-allowed IPs

## Build

### Using xcaddy (recommended)
```bash
# from repo root
xcaddy build \
  --with github.com/you/caddy-jellyfinauth=.
```

### Config
```
# Order before reverse proxies
# Alternatively, can wrap the entire handle { } within a route block, so handle { route { jellyfinauth {}}}
{
  order jellyfinauth before reverse_proxy
}

:8443 {
	handle {
	    // Will reverse proxy accepted traffic to upstream host
	    jellyfinauth {
            upstream        http://jellyfin:8096
            endpoint        /System/Info
            cache_ttl       60m
            timeout         2s

            # preflight policy
            allow_origin                 https://apps.jellyfin.org
            allow_preflight_method       GET POST
            allow_preflight_ua           CrKey/ Chromecast Jellyfin
            preflight_require_known_ip
            temp_allowed_ip_ttl                  15m

            # secondary (temp-allowed) requests policy (inherits if omitted)
            allow_secondary_ua           CrKey/ Chromecast Jellyfin
            allow_secondary_origin       https://apps.jellyfin.org *.jellyfin.org

            allow_cidr       127.0.0.1/32 192.168.0.0/16 172.16.0.0/12
            // Enable if behind a trusted loadbalancer
            //trust_forwarded

            failban_threshold 5
            failban_window    2m
            failban_duration  10m
        }
	}
}
```

Generated with ChatGPT and ClaudeCode
