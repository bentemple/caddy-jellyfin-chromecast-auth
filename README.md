# caddy-jellyfinauth

CONTAINS AI GENERATED CODE.

A tiny Caddy HTTP middleware that:
- Accepts requests from specific IP ranges (CIDR allowlist) without checks.
- Otherwise requires `Authorization: MediaBrowser ...` with `Client="Chromecast"`.
- Sanitizes the header defensively.
- Validates the token by probing Jellyfin (default: `/System/Info`).
- Caches successful `Authorization` headers in memory (TTL).
- On any failure: responds **418 I’m a teapot** and closes the connection.

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
            warm_ip_ttl                  15m

            # secondary (warm) requests policy (inherits if omitted)
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

Generated with ChatGPT
