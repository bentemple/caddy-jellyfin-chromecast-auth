# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Caddy HTTP middleware plugin (`caddy-jellyfinauth`) that provides authentication for Jellyfin, specifically designed for Chromecast integration. The middleware:

- Allows IP allowlist bypassing (CIDR ranges)
- Requires `Authorization: MediaBrowser ...` headers with `Client="Chromecast"`
- Validates tokens against Jellyfin's API
- Implements in-memory caching with TTL
- Includes fail2ban-style protection
- Supports CORS preflight handling
- Allows secondary requests (images/HLS) from temp-allowed IPs

## Build Commands

Build using xcaddy (recommended):
```bash
xcaddy build --with github.com/bentemple/caddy-jellyfin-chromecast-auth=.
```

Update dependencies:
```bash
go mod tidy
```

## Architecture

**Single File Structure**: The entire middleware is implemented in `jellyfinauth.go` (~800 lines).

**Key Components**:
- `Middleware` struct: Main configuration and runtime state
- `ServeHTTP`: Core request handling logic with authentication flow
- Caching system: In-memory cache for valid Authorization headers
- Fail2ban: IP-based failure tracking and temporary bans
- CORS handling: Preflight request validation
- Reverse proxy: Modified `httputil.ReverseProxy` for upstream forwarding

**Authentication Flow**:
1. CORS preflight check → allow if expected
2. IP ban check → reject if banned
3. IP allowlist check → bypass auth if allowed
4. Temp Allowed IP secondary request check → allow images/HLS
5. Authorization header validation → sanitize and validate format
6. Cache check → serve if valid cached token
7. Upstream validation → validate token with Jellyfin API
8. Success → cache token and proxy request

**Security Features**:
- Header sanitization with path traversal protection
- Request rate limiting per IP
- Fail2ban with configurable thresholds
- User-Agent and Origin validation
- API key requirement for HLS requests

## Configuration

The middleware uses Caddyfile syntax with extensive configuration options for timeouts, CORS policies, fail2ban settings, and IP allowlists. See README.md for complete configuration examples.

All responses on authentication failure return HTTP 418 (I'm a teapot) to reduce service fingerprinting.