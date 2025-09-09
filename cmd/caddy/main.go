package main

import (
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/bentemple/caddy-jellyfin-chromecast-auth/jellyfinauth"
	"github.com/caddyserver/caddy/v2/cmd"
)

func main() {
	cmd.Main()
}
