package test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"

	_ "github.com/hslatman/caddy-crowdsec-bouncer/http" // prevent module warning logs
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

func newCaddyVarsContext() (ctx context.Context) {
	ctx = context.WithValue(context.Background(), caddyhttp.VarsCtxKey, map[string]any{})
	return
}

func TestAppSec(t *testing.T) {
	ctx := newCaddyVarsContext()

	container := testutils.NewAppSecContainer(t, ctx)

	config := fmt.Sprintf(`{
		"api_url": %q,
		"api_key": %q,
		"enable_streaming": false,
		"appsec_url": %q
	}`, container.APIUrl(), container.APIKey(), container.AppSecUrl())

	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, "127.0.0.1")
	ctx, _ = httputils.EnsureIP(ctx)
	crowdsec := testutils.NewCrowdSecModule(t, ctx, config)

	err := crowdsec.Start()
	require.NoError(t, err)

	// wait a little bit of time to let the go-cs-bouncer do _some_ work,
	// before it properly returns; seems to hang otherwise on b.wg.Wait().
	time.Sleep(100 * time.Millisecond)

	r := httptest.NewRequest(http.MethodGet, "http://www.example.com", http.NoBody)
	r = r.WithContext(ctx)
	err = crowdsec.CheckRequest(ctx, r)
	require.NoError(t, err)

	r = httptest.NewRequest(http.MethodGet, "http://www.example.com/rpc2", http.NoBody)
	r = r.WithContext(ctx)
	err = crowdsec.CheckRequest(ctx, r)
	require.Error(t, err)

	err = crowdsec.Stop()
	require.NoError(t, err)

	err = crowdsec.Cleanup()
	require.NoError(t, err)
}
