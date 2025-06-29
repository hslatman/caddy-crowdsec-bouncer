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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type fakeModule struct{}

func (m fakeModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.crowdsec",
		New: func() caddy.Module { return new(fakeModule) },
	}
}

func init() {
	caddy.RegisterModule(fakeModule{}) // prevents module warning logs
}

func TestCrowdSecProvisions(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		env       map[string]string
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
		{
			name: "json-env-vars",
			config: `{
				"api_url": "{env.CROWDSEC_TEST_API_URL}",
				"api_key": "{env.CROWDSEC_TEST_API_KEY}",
				"ticker_interval": "{env.CROWDSEC_TEST_TICKER_INTERVAL}"
			}`,
			env: map[string]string{
				"CROWDSEC_TEST_API_URL":         "http://127.0.0.2:8080/",
				"CROWDSEC_TEST_API_KEY":         "env-test-key",
				"CROWDSEC_TEST_TICKER_INTERVAL": "25s",
			},
			assertion: func(tt assert.TestingT, c *CrowdSec) {
				assert.Equal(tt, "http://127.0.0.2:8080/", c.APIUrl)
				assert.Equal(tt, "env-test-key", c.APIKey)
				assert.Equal(tt, "25s", c.TickerInterval)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CrowdSec
			err := json.Unmarshal([]byte(tt.config), &c)
			require.NoError(t, err)

			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
			err = c.Provision(ctx)
			require.NoError(t, err)

			if tt.assertion != nil {
				tt.assertion(t, &c)
			}
		})
	}
}

func TestCrowdSecValidates(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr bool
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
			wantErr: false,
		},
		{
			name: "fail/missing-api-key",
			config: `{
				"api_url": "http://localhost:8080",
				"api_key": ""
			}`,
			wantErr: true,
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

			err = c.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestCrowdSecStreamingBouncerRuntime(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent()) // ignore current ones; they're deep in the Caddy stack
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount += 1
		w.WriteHeader(200) // just accept any request
		w.Write(nil)       // nolint
	}))
	defer srv.Close()

	config := fmt.Sprintf(`{
		"api_url": %q,
		"api_key": "test-key"
	}`, srv.URL) // set test server URL as API URL

	var c CrowdSec
	err := json.Unmarshal([]byte(config), &c)
	require.NoError(t, err)

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = c.Provision(caddyCtx)
	require.NoError(t, err)
	require.True(t, c.isStreamingEnabled())

	err = c.Validate()
	require.NoError(t, err)

	err = c.Start()
	require.NoError(t, err)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		// simulate request coming in and stopping the server from another goroutine
		defer wg.Done()

		// wait a little bit of time to let the go-cs-bouncer do _some_ work,
		// before it properly returns; seems to hang otherwise on b.wg.Wait().
		time.Sleep(100 * time.Millisecond)

		// simulate a lookup
		allowed, decision, err := c.IsAllowed(netip.MustParseAddr("127.0.0.1"))
		assert.NoError(t, err)
		assert.Nil(t, decision)
		assert.True(t, allowed)

		err = c.Stop()
		require.NoError(t, err)

		err = c.Cleanup()
		require.NoError(t, err)
	}()

	// wait for the stop and cleanup process
	wg.Wait()

	// expect a single request to have been performed
	assert.Equal(t, 1, requestCount)
}

func TestCrowdSecliveBouncerRuntime(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent()) // ignore current ones; they're deep in the Caddy stack
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount += 1
		w.WriteHeader(200) // just accept any request
		w.Write(nil)       // nolint
	}))
	defer srv.Close()

	config := fmt.Sprintf(`{
		"api_url": %q,
		"api_key": "test-key",
		"enable_streaming": false
	}`, srv.URL) // set test server URL as API URL

	var c CrowdSec
	err := json.Unmarshal([]byte(config), &c)
	require.NoError(t, err)

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	err = c.Provision(caddyCtx)
	require.NoError(t, err)
	require.False(t, c.isStreamingEnabled())

	err = c.Validate()
	require.NoError(t, err)

	err = c.Start()
	require.NoError(t, err)

	// simulate a lookup
	allowed, decision, err := c.IsAllowed(netip.MustParseAddr("127.0.0.1"))
	assert.NoError(t, err)
	assert.Nil(t, decision)
	assert.True(t, allowed)

	err = c.Stop()
	require.NoError(t, err)

	err = c.Cleanup()
	require.NoError(t, err)

	// expect a single request to have been performed
	assert.Equal(t, 1, requestCount)
}

type fakeDockerProxyModule struct{}

func (m fakeDockerProxyModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "docker_proxy", // fake github.com/lucaslorentz/caddy-docker-proxy/v2
		New: func() caddy.Module { return new(fakeModule) },
	}
}

func TestModuleLogsLowDockerProxyEventThrottleInterval(t *testing.T) {
	caddy.RegisterModule(fakeDockerProxyModule{})

	t.Run("ok/streaming", func(t *testing.T) {
		t.Setenv("CADDY_DOCKER_EVENT_THROTTLE_INTERVAL", "3s")

		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		c := &CrowdSec{logger: logger}

		err := c.checkModules()
		require.NoError(t, err)

		assert.Equal(t, 0, logs.Len())
	})

	t.Run("ok/live", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		v := false
		c := &CrowdSec{logger: logger, EnableStreaming: &v}

		err := c.checkModules()
		require.NoError(t, err)

		assert.Equal(t, 0, logs.Len())
	})

	t.Run("warn-too-low", func(t *testing.T) {
		t.Setenv("CADDY_DOCKER_EVENT_THROTTLE_INTERVAL", "1s")

		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		c := &CrowdSec{logger: logger}

		err := c.checkModules()
		require.NoError(t, err)

		require.Equal(t, 1, logs.Len())
		assert.Equal(t, "using docker_proxy module with a low event throttle interval (<2s) can result in errors; see https://github.com/hslatman/caddy-crowdsec-bouncer/issues/61", logs.All()[0].Message)
	})

	t.Run("warn-not-set", func(t *testing.T) {
		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		c := &CrowdSec{logger: logger}

		err := c.checkModules()
		require.NoError(t, err)

		require.Equal(t, 1, logs.Len())
		assert.Equal(t, "using docker_proxy module with a low event throttle interval (<2s) can result in errors; see https://github.com/hslatman/caddy-crowdsec-bouncer/issues/61", logs.All()[0].Message)
	})

	t.Run("warn-invalid-duration", func(t *testing.T) {
		t.Setenv("CADDY_DOCKER_EVENT_THROTTLE_INTERVAL", "1x")

		core, logs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)

		c := &CrowdSec{logger: logger}

		err := c.checkModules()
		require.NoError(t, err)

		require.Equal(t, 1, logs.Len())
		assert.Equal(t, "using docker_proxy module with a low event throttle interval (<2s) can result in errors; see https://github.com/hslatman/caddy-crowdsec-bouncer/issues/61", logs.All()[0].Message)
	})
}
