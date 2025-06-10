package docker

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/testutils"
)

func TestDocker(t *testing.T) {
	// TODO:
	// Ensure tests are OK when reloading config etc.
	// Additional test with caddy-docker-proxy?

	ctx := context.Background()

	newNetwork, err := network.New(ctx)
	testcontainers.CleanupNetwork(t, newNetwork)
	require.NoError(t, err)

	crowdsec := testutils.NewCrowdSecContainer(t, ctx, newNetwork.Name)
	fmt.Println(crowdsec)

	caddy := testutils.NewContainer(t, ctx, newNetwork.Name)

	time.Sleep(15 * time.Second)

	_ = caddy
	fmt.Println(caddy)
}
