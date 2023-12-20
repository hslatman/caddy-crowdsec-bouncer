package crowdsec

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name             string
		expected         *CrowdSec
		args             args
		wantParseErr     bool
		wantConfigureErr bool
	}{
		{
			name:     "fail/no-args",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec`),
			},
			wantParseErr:     false,
			wantConfigureErr: true,
		},
		{
			name:     "fail/invalid-duration",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
					ticker_interval 30x
				}`),
			},
			wantParseErr:     true,
			wantConfigureErr: false,
		},
		{
			name:     "fail/unknown-token",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
					unknown_token 42
				}`),
			},
			wantParseErr:     true,
			wantConfigureErr: false,
		},
		{
			name: "ok/basic",
			expected: &CrowdSec{
				APIUrl:          "http://127.0.0.1:8080/",
				APIKey:          "some_random_key",
				EnableStreaming: true,
				EnableHardFails: false,
			},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
				}`),
			},
			wantParseErr:     false,
			wantConfigureErr: false,
		},
		{
			name: "ok/full",
			expected: &CrowdSec{
				APIUrl:          "http://127.0.0.1:8080/",
				APIKey:          "some_random_key",
				TickerInterval:  "33s",
				EnableStreaming: false,
				EnableHardFails: true,
			},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
					ticker_interval 33s
					disable_streaming
					enable_hard_fails
				}`),
			},
			wantParseErr:     false,
			wantConfigureErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonApp, err := parseCrowdSec(tt.args.d, nil)
			if tt.wantParseErr {
				assert.Error(t, err)
				return
			}
			app, ok := jsonApp.(httpcaddyfile.App)
			if !ok {
				t.Fatal("not a httpcaddyfile.App instance")
			}
			if app.Name != "crowdsec" {
				t.Errorf("expected crowdsec app name")
			}
			c := &CrowdSec{}
			if err := json.Unmarshal(app.Value, c); err != nil {
				t.Fatal(err)
			}
			if tt.wantConfigureErr {
				// TODO: do we still need configure()?
				// if err := c.configure(); (err != nil) != tt.wantConfigureErr {
				// 	t.Errorf("CrowdSec.configure) error = %v, wantConfigureErr %v", err, tt.wantConfigureErr)
				// 	return
				// }
				return
			}

			// TODO: properly use go-cmp and get unexported fields to work?
			if tt.expected.APIUrl != "" {
				if tt.expected.APIUrl != c.APIUrl {
					t.Errorf("got: %s, want: %s", c.APIUrl, tt.expected.APIUrl)
				}
			}
			if tt.expected.APIKey != "" {
				if tt.expected.APIKey != c.APIKey {
					t.Errorf("got: %s, want: %s", c.APIKey, tt.expected.APIKey)
				}
			}
			if tt.expected.TickerInterval != "" {
				if tt.expected.TickerInterval != c.TickerInterval {
					t.Errorf("got: %s, want: %s", c.TickerInterval, tt.expected.TickerInterval)
				}
			}
			if tt.expected.EnableStreaming != c.EnableStreaming {
				t.Errorf("got: %t, want: %t", c.EnableStreaming, tt.expected.EnableStreaming)
			}
			if tt.expected.EnableHardFails != c.EnableHardFails {
				t.Errorf("got: %t, want: %t", c.EnableHardFails, tt.expected.EnableHardFails)
			}
		})
	}
}
