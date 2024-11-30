package version

import (
	"runtime/debug"
)

const (
	modulePath = "github.com/hslatman/caddy-crowdsec-bouncer"
	fallback   = "v0.8.0"
)

func Current() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fallback
	}

	for _, d := range info.Deps {
		if d.Path == modulePath {
			return d.Version
		}
	}

	return fallback
}
