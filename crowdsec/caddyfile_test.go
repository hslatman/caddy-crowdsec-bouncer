package crowdsec

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	trueValue := true
	falseValue := false
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name     string
		expected *CrowdSec
		args     args
		wantErr  bool
	}{
		{
			name:     "no args",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec`),
			},
			wantErr: false,
		},
		{
			name: "basic",
			expected: &CrowdSec{
				APIUrl: "http://127.0.0.1:8080",
				APIKey: "some_random_key",
			},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
				}`),
			},
			wantErr: false,
		},
		{
			name: "full",
			expected: &CrowdSec{
				APIUrl:          "http://127.0.0.1:8080",
				APIKey:          "some_random_key",
				TickerInterval:  "33s",
				EnableStreaming: &falseValue,
				EnableHardFails: &trueValue,
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
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CrowdSec{}
			if _, err := parseCaddyfileGlobalOption(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("CrowdSec.UnmarshalCaddyfile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// TODO: properly use go-cmp and get unexported fields to work
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
			if tt.expected.EnableStreaming != nil {
				if *tt.expected.EnableStreaming != *c.EnableStreaming {
					t.Errorf("got: %t, want: %t", *c.EnableStreaming, *tt.expected.EnableStreaming)
				}
			}
			if tt.expected.EnableHardFails != nil {
				if *tt.expected.EnableHardFails != *c.EnableHardFails {
					t.Errorf("got: %t, want: %t", *c.EnableHardFails, *tt.expected.EnableHardFails)
				}
			}
		})
	}
}
