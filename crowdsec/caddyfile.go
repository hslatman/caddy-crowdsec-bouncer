package crowdsec

import (
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile sets up the CrowdSec module from Caddyfile tokens.
func (c *CrowdSec) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {

	trueValue := true
	falseValue := false

	if !d.Next() {
		return d.Err("expected tokens")
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "api_url":
			if !d.NextArg() {
				return d.ArgErr()
			}
			u, err := url.Parse(d.Val())
			if err != nil {
				return d.Errf("invalid URL %s: %v", d.Val(), err)
			}
			c.APIUrl = u.String()
		case "api_key":
			if !d.NextArg() {
				return d.ArgErr()
			}
			c.APIKey = d.Val()
		case "ticker_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			interval, err := time.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("invalid duration %s: %v", d.Val(), err)
			}
			c.TickerInterval = interval.String()
		case "disable_streaming":
			if d.NextArg() {
				return d.ArgErr()
			}
			c.EnableStreaming = &falseValue
		case "enable_hard_fails":
			if d.NextArg() {
				return d.ArgErr()
			}
			c.EnableHardFails = &trueValue
		}

	}

	return nil
}
