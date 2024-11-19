package testutils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
)

const testAPIKey = "testbouncer1key"

type container struct {
	c        testcontainers.Container
	endpoint string
	appsec   string
}

func NewCrowdSecContainer(t *testing.T, ctx context.Context) *container {
	t.Helper()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "crowdsecurity/crowdsec:latest",
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForLog("CrowdSec Local API listening on 0.0.0.0:8080"),
			Env: map[string]string{
				"BOUNCER_KEY_testbouncer1": testAPIKey,
				"DISABLE_ONLINE_API":       "true",
			},
		},
		Started: true,
		Logger:  testcontainers.TestLogger(t),
	})
	require.NoError(t, err)
	require.NotNil(t, c)
	t.Cleanup(func() { c.Terminate(ctx) })

	endpointPort, err := c.MappedPort(ctx, "8080/tcp")
	require.NoError(t, err)

	return &container{
		c:        c,
		endpoint: fmt.Sprintf("http://localhost:%d", endpointPort.Int()),
	}
}

func (c *container) APIUrl() string {
	return c.endpoint
}

func (c *container) APIKey() string {
	return testAPIKey
}

func (c *container) AppSecUrl() string {
	return c.appsec
}

func (c *container) Exec(ctx context.Context, cmd []string) (int, io.Reader, error) {
	return c.c.Exec(ctx, cmd, []exec.ProcessOption{}...)
}

const appSecConfig = `listen_addr: 0.0.0.0:7422
appsec_config: crowdsecurity/appsec-default
name: test
source: appsec
labels:
  type: appsec
`

func NewAppSecContainer(t *testing.T, ctx context.Context) *container {
	t.Helper()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "crowdsecurity/crowdsec:latest",
			ExposedPorts: []string{"8080/tcp", "7422/tcp"},
			WaitingFor:   wait.ForLog("CrowdSec Local API listening on 0.0.0.0:8080"),
			Env: map[string]string{
				"BOUNCER_KEY_testbouncer1": testAPIKey,
				"DISABLE_ONLINE_API":       "true",
			},
			Files: []testcontainers.ContainerFile{
				{
					Reader:            bytes.NewBuffer([]byte(appSecConfig)),
					ContainerFilePath: "/etc/crowdsec/acquis.d/appsec.yaml",
				},
			},
		},
		Started: true,
		Logger:  testcontainers.TestLogger(t),
	})
	require.NoError(t, err)
	require.NotNil(t, c)
	t.Cleanup(func() { c.Terminate(ctx) })

	code, reader, err := c.Exec(ctx, []string{"cscli", "collections", "install", "crowdsecurity/appsec-virtual-patching"})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	LogContainerOutput(t, reader)

	code, reader, err = c.Exec(ctx, []string{"cscli", "collections", "install", "crowdsecurity/appsec-generic-rules"})
	require.NoError(t, err)
	require.Equal(t, 0, code)
	LogContainerOutput(t, reader)

	time.Sleep(2 * time.Second)

	err = c.Stop(ctx, nil)
	require.NoError(t, err)
	err = c.Start(ctx)
	require.NoError(t, err)

	endpointPort, err := c.MappedPort(ctx, "8080/tcp")
	require.NoError(t, err)

	appsecPort, err := c.MappedPort(ctx, "7422/tcp")
	require.NoError(t, err)

	return &container{
		c:        c,
		endpoint: fmt.Sprintf("http://localhost:%d", endpointPort.Int()),
		appsec:   fmt.Sprintf("http://localhost:%d", appsecPort.Int()),
	}
}

func NewCrowdSecModule(t *testing.T, ctx context.Context, config string) *crowdsec.CrowdSec {
	t.Helper()

	var c crowdsec.CrowdSec
	err := json.Unmarshal([]byte(config), &c)
	require.NoError(t, err)

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: ctx})
	t.Cleanup(cancel)

	err = c.Provision(caddyCtx)
	require.NoError(t, err)

	err = c.Validate()
	require.NoError(t, err)

	return &c
}

func LogContainerOutput(t *testing.T, reader io.Reader) {
	t.Helper()

	buf := new(strings.Builder)
	_, err := io.Copy(buf, reader)
	require.NoError(t, err)
	t.Log(buf.String())
}
