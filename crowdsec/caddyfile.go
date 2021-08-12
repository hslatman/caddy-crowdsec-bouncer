package crowdsec

import (
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func parseCaddyfileGlobalOption(d *caddyfile.Dispenser) (interface{}, error) {

	// TODO: make this work similar to the handler? Or doesn't that work for this
	// app level module, because of shared config etc.

	cfg = &config{
		TickerInterval:  defaultTickerInterval,
		EnableStreaming: defaultStreamingEnabled,
		EnableHardFails: defaultHardFailsEnabled,
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
			cfg.APIUrl = u.String()
		case "api_key":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.APIKey = d.Val()
		case "ticker_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			interval, err := time.ParseDuration(d.Val())
			if err != nil {
				return nil, d.Errf("invalid duration %s: %v", d.Val(), err)
			}
			cfg.TickerInterval = interval.String()
		case "disable_streaming":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.EnableStreaming = false
		case "enable_hard_fails":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			cfg.EnableHardFails = true
		default:
			return nil, d.Errf("invalid configuration token provided: %s", d.Val())
		}
	}

	return nil, nil
}
