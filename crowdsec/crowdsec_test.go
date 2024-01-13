// Copyright 2020 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crowdsec

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrowdSec_Provision(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		assertion func(tt assert.TestingT, c *CrowdSec)
		wantErr   bool
	}{
		{
			name: "ok",
			config: `{
				"api_url": "http://localhost:8080",
				"api_key": "test-key",
				"ticker_interval": "10s",
				"enable_streaming": false, 
				"enable_hard_fails": true
			}`,
			assertion: func(tt assert.TestingT, c *CrowdSec) {
				assert.Equal(tt, "http://localhost:8080", c.APIUrl)
				assert.Equal(tt, "test-key", c.APIKey)
				assert.Equal(tt, "10s", c.TickerInterval)
				assert.False(tt, c.isStreamingEnabled())
				assert.True(tt, c.shouldFailHard())
			},
			wantErr: false,
		},
		{
			name:   "defaults",
			config: `{}`,
			assertion: func(tt assert.TestingT, c *CrowdSec) {
				assert.Equal(tt, "http://127.0.0.1:8080/", c.APIUrl)
				assert.Equal(tt, "", c.APIKey)
				assert.Equal(tt, "60s", c.TickerInterval)
				assert.True(tt, c.isStreamingEnabled())
				assert.False(tt, c.shouldFailHard())
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CrowdSec
			err := json.Unmarshal([]byte(tt.config), &c)
			require.NoError(t, err)

			ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
			err = c.Provision(ctx)
			require.NoError(t, err)

			if tt.assertion != nil {
				tt.assertion(t, &c)
			}
		})
	}
}
