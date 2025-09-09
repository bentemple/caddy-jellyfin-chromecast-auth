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
:8443 {
	handle {
		jellyfinauth {
			upstream        http://localhost:8096
			endpoint        /System/Info
			require_client  Chromecast
			cache_ttl       10m
			timeout         2s

			# Always allow these ranges
			allow_cidr      192.168.0.0/16 10.0.0.0/8
			allow_cidr      172.16.0.0/12

			# If behind a trusted proxy/LB
			trust_forwarded
		}

		root * /srv/site
		file_server
	}
}
```

Generated with ChatGPT
