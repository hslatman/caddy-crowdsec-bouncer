package test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/hslatman/caddy-crowdsec-bouncer/http" // prevent module warning logs
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

func newCaddyVarsContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{})
}

func TestAppSec(t *testing.T) {
	container := testutils.NewAppSecContainer(t)

	config := fmt.Sprintf(`{
		"api_url": %q,
		"api_key": %q,
		"enable_streaming": false,
		"appsec_url": %q
	}`, container.APIUrl(), container.APIKey(), container.AppSecUrl())

	ctx := t.Context()
	ctx = newCaddyVarsContext(ctx)
	caddyhttp.SetVar(ctx, caddyhttp.ClientIPVarKey, "127.0.0.1")
	ctx, _ = httputils.EnsureIP(ctx)
	crowdsec := testutils.NewCrowdSecModule(t, ctx, config)

	err := crowdsec.Start()
	require.NoError(t, err)

	// wait a little bit of time to let the go-cs-bouncer do _some_ work,
	// before it properly returns; seems to hang otherwise on b.wg.Wait().
	time.Sleep(100 * time.Millisecond)

	// simulate a request that is allowed
	r := httptest.NewRequest(http.MethodGet, "http://www.example.com", http.NoBody)
	r = r.WithContext(ctx)
	r.Header.Set("User-Agent", "test-appsec")
	err = crowdsec.CheckRequest(ctx, r)
	assert.NoError(t, err)

	// simulate a request that'll be banned using the currently installed rules, similar
	// to https://docs.crowdsec.net/docs/appsec/installation/#making-sure-everything-works.
	// This will simulate exploitation of JetBrains Teamcity Auth Bypass; CVE-2023-42793.
	r = httptest.NewRequest(http.MethodGet, "http://www.example.com/rpc2", http.NoBody)
	r = r.WithContext(ctx)
	r.Header.Set("User-Agent", "test-appsec")
	err = crowdsec.CheckRequest(ctx, r)
	assert.Error(t, err)

	// simulate a request exploiting Ivanti EPM - SQLi; CVE-2024-29824.
	body := bytes.NewBufferString("blabla 'xp_cmdshell' blabla")
	r = httptest.NewRequest(http.MethodPost, "http://www.example.com/wsstatusevents/eventhandler.asmx", body)
	r = r.WithContext(ctx)
	r.Header.Set("User-Agent", "test-appsec")
	err = crowdsec.CheckRequest(ctx, r)
	assert.Error(t, err)

	// simulate a request exploiting Dasan GPON RCE; CVE-2018-10562
	data := url.Values{}
	data.Set("dest_host", "\\`arg\\`;bla")
	r = httptest.NewRequest(http.MethodPost, "http://www.example.com/gponform/diag_form", strings.NewReader(data.Encode()))
	r = r.WithContext(ctx)
	r.Header.Set("User-Agent", "test-appsec")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	err = crowdsec.CheckRequest(ctx, r)
	assert.Error(t, err)

	// simulate a request exploiting WooCommerce auth bypass; CVE-2023-28121, ensuring
	// that headers are passed correctly.
	body = bytes.NewBufferString("some body")
	r = httptest.NewRequest(http.MethodPost, "http://www.example.com", body)
	r = r.WithContext(ctx)
	r.Header.Set("User-Agent", "test-appsec")
	r.Header.Set("x-wcpay-platform-checkout-user", "x-wcpay-platform-checkout-user")
	err = crowdsec.CheckRequest(ctx, r)
	assert.Error(t, err)

	err = crowdsec.Stop()
	require.NoError(t, err)

	err = crowdsec.Cleanup()
	require.NoError(t, err)
}
