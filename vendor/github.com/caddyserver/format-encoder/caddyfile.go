// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package formatencoder

import (
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile sets up the module from Caddyfile tokens. Syntax:
//
//     formatted [<template>] [{
//          placeholder	[<placeholder>]
//     }]
//
// If the value of "template" is omitted, Common Log Format is assumed.
// See the godoc on the LogEncoderConfig type for the syntax of
// subdirectives that are common to most/all encoders.
func (se *FormattedEncoder) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 0:
			se.Template = commonLogFormat
		default:
			se.Template = strings.Join(args, " ")
		}

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			subdir := d.Val()
			var arg string
			if !d.AllArgs(&arg) {
				return d.ArgErr()
			}
			switch subdir {
			case "message_key":
				se.MessageKey = &arg
			case "level_key":
				se.LevelKey = &arg
			case "time_key":
				se.TimeKey = &arg
			case "name_key":
				se.NameKey = &arg
			case "caller_key":
				se.CallerKey = &arg
			case "stacktrace_key":
				se.StacktraceKey = &arg
			case "line_ending":
				se.LineEnding = &arg
			case "time_format":
				se.TimeFormat = arg
			case "level_format":
				se.LevelFormat = arg
			case "placeholder":
				se.Placeholder = arg
			default:
				return d.Errf("unrecognized subdirective %s", subdir)
			}
		}
	}
	return nil
}
