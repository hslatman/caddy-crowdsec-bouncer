//go:build e2e

// Package e2e runs the bouncer end to end: real Caddy configurations loaded into
// an in-process Caddy instance, real HTTP and TCP requests, and a real CrowdSec
// container behind them.
//
// Caddy keeps its configuration in process-global state, so tests in this
// package must never call t.Parallel.
//
// Run with:
//
//	go test -race -tags=e2e -timeout=25m ./test/e2e/...
package e2e

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	// register the Caddy modules under test
	_ "github.com/hslatman/caddy-crowdsec-bouncer/appsec"
	_ "github.com/hslatman/caddy-crowdsec-bouncer/http"
	_ "github.com/hslatman/caddy-crowdsec-bouncer/layer4"

	// register the layer4 app and its echo handler, needed by layer4_test.go.
	// l4echo is used rather than l4proxy because it depends only on packages
	// already required by this module, whereas l4proxy would add go-proxyproto
	// to go.mod purely for tests.
	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4echo"

	// The http app and static_response both live in modules/caddyhttp, which the
	// bouncer's own http package already imports, so no additional Caddy module
	// bundle is needed here. Importing modules/standard instead would pull a
	// large set of new dependencies into go.mod purely for tests.

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

// Containers are started lazily and shared by every test in the package: a
// CrowdSec container costs seconds to start and the AppSec pair costs minutes,
// which is too much to pay per test. Tests stay independent by each banning
// their own address from [testutils.NextTestIP].
var (
	crowdsecOnce      sync.Once
	crowdsecContainer *testutils.Container
	crowdsecTerminate func()
	crowdsecErr       error

	appsecOnce      sync.Once
	appsecContainer *testutils.Container
	appsecTerminate func()
	appsecErr       error
)

// sharedCrowdSec returns the CrowdSec container shared by this package,
// starting it on first use.
func sharedCrowdSec(t *testing.T) *testutils.Container {
	t.Helper()
	skipIfShort(t)

	crowdsecOnce.Do(func() {
		crowdsecContainer, crowdsecTerminate, crowdsecErr = testutils.StartCrowdSecContainer(context.Background(), nil)
	})
	require.NoError(t, crowdsecErr, "failed starting shared CrowdSec container")

	return crowdsecContainer
}

// sharedAppSec returns the CrowdSec container with AppSec enabled shared by this
// package, starting it on first use. Provisioning installs the WAF collections
// and takes minutes.
func sharedAppSec(t *testing.T) *testutils.Container {
	t.Helper()
	skipIfShort(t)

	appsecOnce.Do(func() {
		appsecContainer, appsecTerminate, appsecErr = testutils.StartAppSecContainer(context.Background(), nil)
	})
	require.NoError(t, appsecErr, "failed starting shared AppSec container")

	return appsecContainer
}

func skipIfShort(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping end-to-end test in short mode")
	}
}

func TestMain(m *testing.M) {
	code := m.Run()

	// containers are shared across the package, so they can only be torn down
	// once every test has finished
	if crowdsecTerminate != nil {
		crowdsecTerminate()
	}
	if appsecTerminate != nil {
		appsecTerminate()
	}

	os.Exit(code)
}
