package crowdsec

import (
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func parseCrowdSec(d *caddyfile.Dispenser, existingVal any) (any, error) {
	tv := true
	fv := false
	cs := &CrowdSec{
		TickerInterval:  "60s",
		EnableStreaming: &tv,
		EnableHardFails: &fv,
	}

	if !d.Next() {
		return nil, d.Err("expected tokens")
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "api_url":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			u, err := url.Parse(d.Val())
			if err != nil {
				return nil, d.Errf("invalid URL %s: %v", d.Val(), err)
			}
			if u.Scheme == "" {
				return nil, d.Errf("URL %q does not have a scheme (i.e https)", u.String())
			}
			s := u.String()
			if !strings.HasSuffix(s, "/") {
				s = s + "/"
			}
			cs.APIUrl = s
		case "api_key":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cs.APIKey = d.Val()
		case "ticker_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			interval, err := time.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("invalid duration %s: %v", d.Val(), err)
			}
			cs.TickerInterval = interval.String()
		case "disable_streaming":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			cs.EnableStreaming = &fv
		case "enable_hard_fails":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			cs.EnableHardFails = &tv
		default:
			return nil, d.Errf("invalid configuration token provided: %s", d.Val())
		}
	}

	return httpcaddyfile.App{
		Name:  "crowdsec",
		Value: caddyconfig.JSON(cs, nil),
	}, nil
}
