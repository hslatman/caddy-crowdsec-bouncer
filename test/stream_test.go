package test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/hslatman/caddy-crowdsec-bouncer/http" // prevent module warning logs
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

func TestStreamingBouncer(t *testing.T) {
	ctx := context.Background()

	container := testutils.NewCrowdSecContainer(t, ctx)

	config := fmt.Sprintf(`{
		"api_url": %q,
		"api_key": %q,
		"ticker_interval": "1s"
	}`, container.APIUrl(), container.APIKey())

	crowdsec := testutils.NewCrowdSecModule(t, ctx, config)

	err := crowdsec.Start()
	require.NoError(t, err)

	// wait a little bit of time to let the go-cs-bouncer do _some_ work,
	// before it properly returns; seems to hang otherwise on b.wg.Wait().
	time.Sleep(100 * time.Millisecond)

	// simulate a lookup; no decisions available, so will be allowed
	allowed, decision, err := crowdsec.IsAllowed(netip.MustParseAddr("127.0.0.1"))
	assert.NoError(t, err)
	assert.True(t, allowed)
	assert.Nil(t, decision)

	// add a ban for 127.0.0.1
	code, reader, err := container.Exec(ctx, []string{"cscli", "decisions", "add", "--ip", "127.0.0.1", "--duration", "20s"})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	testutils.LogContainerOutput(t, reader)

	// wait 3 seconds to obtain new decision; streaming ticker interval is 1 second, so should be enough time
	time.Sleep(3 * time.Second)

	// simulate a lookup; 127.0.0.1 should now be banned
	allowed, decision, err = crowdsec.IsAllowed(netip.MustParseAddr("127.0.0.1"))
	assert.NoError(t, err)
	assert.False(t, allowed)
	if assert.NotNil(t, decision) {
		assert.Equal(t, "ban", *decision.Type)
		assert.Equal(t, "127.0.0.1", *decision.Value)
		assert.Equal(t, "Ip", *decision.Scope)
	}

	err = crowdsec.Stop()
	require.NoError(t, err)

	err = crowdsec.Cleanup()
	require.NoError(t, err)
}
