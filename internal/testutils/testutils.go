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
	"github.com/stretchr/testify/assert"
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
			Image:        "crowdsecurity/crowdsec:slim",
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForLog("CrowdSec Local API listening on 0.0.0.0:8080"),
			Env: map[string]string{
				"BOUNCER_KEY_testbouncer1": testAPIKey,
				"DISABLE_ONLINE_API":       "true",
				"NO_HUB_UPGRADE":           "true",
			},
		},
		Started: true,
		Logger:  testcontainers.TestLogger(t),
	})
	require.NoError(t, err)
	require.NotNil(t, c)
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	endpointPort, err := c.MappedPort(ctx, "8080/tcp")
	require.NoError(t, err)

	return &container{
		c:        c,
		endpoint: fmt.Sprintf("http://127.0.0.1:%d", endpointPort.Int()),
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
name: appsec-test
source: appsec
labels:
  type: appsec
`

func NewAppSecContainer(t *testing.T, ctx context.Context) *container {
	t.Helper()

	// shared data between initialization and actual AppSec container
	mounts := testcontainers.ContainerMounts{
		{
			Source: testcontainers.GenericVolumeMountSource{
				Name: "crowdsec-etc",
			},
			Target: "/etc/crowdsec",
		},
		{
			Source: testcontainers.GenericVolumeMountSource{
				Name: "crowdsec-data",
			},
			Target: "/var/lib/crowdsec/data",
		},
	}

	// AppSec requires some WAF rules to be present, so we start by initializing
	// a container, installing the required collections, and then stopping it again.
	initContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "crowdsecurity/crowdsec:slim",
			Mounts:       mounts,
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForLog("CrowdSec Local API listening on 0.0.0.0:8080"),
			Env: map[string]string{
				"BOUNCER_KEY_testbouncer1": testAPIKey,
				"DISABLE_ONLINE_API":       "true",
				"NO_HUB_UPGRADE":           "true",
			},
		},
		Started: true,
		Logger:  testcontainers.TestLogger(t),
	})
	require.NoError(t, err)
	require.NotNil(t, initContainer)

	// install some AppSec rule collections
	code, reader, err := initContainer.Exec(ctx, []string{"cscli", "collections", "install", "crowdsecurity/appsec-virtual-patching"})
	assert.NoError(t, err)
	assert.Equal(t, 0, code)
	LogContainerOutput(t, reader)

	code, reader, err = initContainer.Exec(ctx, []string{"cscli", "collections", "install", "crowdsecurity/appsec-generic-rules"})
	assert.NoError(t, err)
	assert.Equal(t, 0, code)
	LogContainerOutput(t, reader)

	// allow container some slack
	time.Sleep(1 * time.Second)

	// cleanly stop the initialization container
	duration := 3 * time.Second
	err = initContainer.Stop(ctx, &duration)
	require.NoError(t, err)
	err = initContainer.Terminate(ctx)
	require.NoError(t, err)

	// create the actual AppSec container
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "crowdsecurity/crowdsec:slim",
			Mounts:       mounts,
			ExposedPorts: []string{"8080/tcp", "7422/tcp"},
			WaitingFor:   wait.ForLog("Appsec Runner ready to process event"),
			Env: map[string]string{
				"BOUNCER_KEY_testbouncer1": testAPIKey,
				"DISABLE_ONLINE_API":       "true",
				"NO_HUB_UPGRADE":           "true",
				"LEVEL_DEBUG":              "true",
				"DEBUG":                    "true",
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
	t.Cleanup(func() { _ = c.Terminate(ctx) })

	endpointPort, err := c.MappedPort(ctx, "8080/tcp")
	require.NoError(t, err)

	appsecPort, err := c.MappedPort(ctx, "7422/tcp")
	require.NoError(t, err)

	return &container{
		c:        c,
		endpoint: fmt.Sprintf("http://127.0.0.1:%d", endpointPort.Int()),
		appsec:   fmt.Sprintf("http://127.0.0.1:%d", appsecPort.Int()),
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

	if reader == nil {
		return
	}

	buf := new(strings.Builder)
	_, err := io.Copy(buf, reader)
	require.NoError(t, err)
	t.Log(buf.String())
}
