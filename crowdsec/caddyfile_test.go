package crowdsec

import (
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	tv := true
	fv := false
	type args struct {
		d *caddyfile.Dispenser
	}
	tests := []struct {
		name         string
		expected     *CrowdSec
		args         args
		wantParseErr bool
	}{
		{
			name:     "fail/missing tokens",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(``),
			},
			wantParseErr: true,
		},
		{
			name:     "fail/not-crowdsec",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`not-crowdsec`),
			},
			wantParseErr: true,
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
			wantParseErr: true,
		},
		{
			name:     "fail/no-api-url",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url 
					api_key some_random_key
					ticker_interval 30x
				}`),
			},
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-api-url",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://\x00/
					api_key some_random_key
					ticker_interval 30x
				}`),
			},
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-api-url-no-scheme",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url example.com
					api_key some_random_key
					ticker_interval 30x
				}`),
			},
			wantParseErr: true,
		},
		{
			name:     "fail/missing-api-key",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key 
				}`),
			},
			wantParseErr: true,
		},
		{
			name:     "fail/missing-ticker-interval",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key test-key
					ticker_interval
				}`),
			},
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-streaming",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key test-key
					ticker_interval 30s
					disable_streaming absolutely
				}`),
			},
			wantParseErr: true,
		},
		{
			name:     "fail/invalid-streaming",
			expected: &CrowdSec{},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key test-key
					ticker_interval 30s
					disable_streaming
					enable_hard_fails yo
				}`),
			},
			wantParseErr: true,
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
			wantParseErr: true,
		},
		{
			name: "ok/basic",
			expected: &CrowdSec{
				APIUrl:          "http://127.0.0.1:8080/",
				APIKey:          "some_random_key",
				TickerInterval:  "60s",
				EnableStreaming: &tv,
				EnableHardFails: &fv,
			},
			args: args{
				d: caddyfile.NewTestDispenser(`crowdsec {
					api_url http://127.0.0.1:8080 
					api_key some_random_key
				}`),
			},
			wantParseErr: false,
		},
		{
			name: "ok/full",
			expected: &CrowdSec{
				APIUrl:          "http://127.0.0.1:8080/",
				APIKey:          "some_random_key",
				TickerInterval:  "33s",
				EnableStreaming: &fv,
				EnableHardFails: &tv,
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
			wantParseErr: false,
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
			require.True(t, ok)
			assert.Equal(t, "crowdsec", app.Name)

			var c CrowdSec
			err = json.Unmarshal(app.Value, &c)
			require.NoError(t, err)

			assert.Equal(t, tt.expected.APIUrl, c.APIUrl)
			assert.Equal(t, tt.expected.APIKey, c.APIKey)
			assert.Equal(t, tt.expected.TickerInterval, c.TickerInterval)
			assert.Equal(t, tt.expected.isStreamingEnabled(), c.isStreamingEnabled())
			assert.Equal(t, tt.expected.shouldFailHard(), c.shouldFailHard())
		})
	}
}
