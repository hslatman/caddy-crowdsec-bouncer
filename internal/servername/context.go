package servername

import (
	"context"
	"fmt"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	l4 "github.com/mholt/caddy-l4/layer4"
)

const unknownServerName = "UNKNOWN"

// FromContext extracts the current server name from the
// [context.Context]. Returns "UNKNOWN" string if none is available.
func FromContext(ctx context.Context) string {
	srv, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	if !ok || srv == nil {
		return ""
	}

	if srv.Name() == "" {
		return unknownServerName
	}

	return srv.Name()
}

// FromConnection extracts the current server name from the
// [l4.Connection]. Returns "UNKNOWN" string if none is available.
func FromConnection(cx *l4.Connection) string {
	server := FromContext(cx.Context) // TODO: change layer4 to also have a server name; they're named
	if server == "" {
		server = cx.LocalAddr().String()
	}

	if server == "" {
		return unknownServerName
	}

	return fmt.Sprintf("layer4-%s", server)
}
