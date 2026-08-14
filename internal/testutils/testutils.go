package testutils

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
)

const (
	containerImage = "crowdsecurity/crowdsec:slim"
	//containerImage = "crowdsec-local"
	testAPIKey = "testbouncer1key"
)

// Container is a running CrowdSec instance, optionally with its AppSec
// component enabled.
type Container struct {
	c        testcontainers.Container
	endpoint string
	appsec   string
}

func (c *Container) APIUrl() string {
	return c.endpoint
}

func (c *Container) APIKey() string {
	return testAPIKey
}

func (c *Container) AppSecUrl() string {
	return c.appsec
}

func (c *Container) Exec(ctx context.Context, cmd []string) (int, io.Reader, error) {
	return c.c.Exec(ctx, cmd, []exec.ProcessOption{}...)
}

// ExecCombined runs cmd and returns its exit code along with the combined
// output, demultiplexed from Docker's stream framing so it can be parsed.
func (c *Container) ExecCombined(ctx context.Context, cmd []string) (int, string, error) {
	code, reader, err := c.c.Exec(ctx, cmd, exec.Multiplexed())
	if err != nil {
		return code, "", err
	}

	b, err := io.ReadAll(reader)
	if err != nil {
		return code, "", err
	}

	return code, strings.TrimSpace(string(b)), nil
}

// NewCrowdSecContainer starts a CrowdSec container scoped to the lifetime of t.
//
// Prefer [StartCrowdSecContainer] when the container should be shared by an
// entire test package: t.Cleanup would otherwise terminate it after the first
// test finishes.
func NewCrowdSecContainer(t *testing.T) *Container {
	t.Helper()

	c, terminate, err := StartCrowdSecContainer(t.Context(), log.TestLogger(t))
	require.NoError(t, err)
	require.NotNil(t, c)
	t.Cleanup(terminate)

	return c
}

// StartCrowdSecContainer starts a CrowdSec container and returns it along with
// a termination function. The logger may be nil, in which case testcontainers'
// default global logger is used.
func StartCrowdSecContainer(ctx context.Context, logger log.Logger) (*Container, func(), error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        containerImage,
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForLog("CrowdSec Local API listening on 0.0.0.0:8080"),
			Env: map[string]string{
				"BOUNCER_KEY_testbouncer1":        testAPIKey,
				"DISABLE_ONLINE_API":              "true",
				"NO_HUB_UPGRADE":                  "true",
				"CROWDSEC_BYPASS_DB_VOLUME_CHECK": "true",
			},
		},
		Started: true,
		Logger:  logger,
	})
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed starting CrowdSec container: %w", err)
	}

	terminate := terminateFunc(c)

	endpointPort, err := c.MappedPort(ctx, "8080/tcp")
	if err != nil {
		terminate()
		return nil, func() {}, fmt.Errorf("failed determining mapped port: %w", err)
	}

	return &Container{
		c:        c,
		endpoint: fmt.Sprintf("http://127.0.0.1:%s", endpointPort.Port()),
	}, terminate, nil
}

const appSecConfig = `listen_addr: 0.0.0.0:7422
appsec_config: crowdsecurity/appsec-default
name: appsec-test
source: appsec
labels:
  type: appsec
`

// NewAppSecContainer starts a CrowdSec container with AppSec enabled, scoped to
// the lifetime of t.
//
// Prefer [StartAppSecContainer] when the container should be shared by an entire
// test package; provisioning takes minutes because the WAF collections have to
// be installed first.
func NewAppSecContainer(t *testing.T) *Container {
	t.Helper()

	c, terminate, err := StartAppSecContainer(t.Context(), log.TestLogger(t))
	require.NoError(t, err)
	require.NotNil(t, c)
	t.Cleanup(terminate)

	return c
}

// StartAppSecContainer starts a CrowdSec container with the AppSec component
// enabled, and returns it along with a termination function. The logger may be
// nil, in which case testcontainers' default global logger is used.
//
// AppSec requires WAF rules to be present, so an initialization container is
// started first to install the required collections into a pair of volumes that
// the real container then reuses.
func StartAppSecContainer(ctx context.Context, logger log.Logger) (*Container, func(), error) {
	// Volume names must be unique per run: `go test` runs packages as parallel
	// processes, and fixed names would make concurrent packages share (and
	// corrupt) each other's CrowdSec configuration and hub data.
	suffix, err := randomSuffix()
	if err != nil {
		return nil, func() {}, err
	}

	var (
		etcVolume  = "crowdsec-etc-" + suffix
		dataVolume = "crowdsec-data-" + suffix
	)

	mounts := testcontainers.ContainerMounts{
		{
			Source: testcontainers.GenericVolumeMountSource{Name: etcVolume},
			Target: "/etc/crowdsec",
		},
		{
			Source: testcontainers.GenericVolumeMountSource{Name: dataVolume},
			Target: "/var/lib/crowdsec/data",
		},
	}

	initContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        containerImage,
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
		Logger:  logger,
	})
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed starting AppSec init container: %w", err)
	}

	for _, collection := range []string{
		"crowdsecurity/appsec-virtual-patching",
		"crowdsecurity/appsec-generic-rules",
	} {
		code, _, err := initContainer.Exec(ctx, []string{"cscli", "collections", "install", collection})
		if err != nil {
			_ = initContainer.Terminate(ctx)
			return nil, func() {}, fmt.Errorf("failed installing %s: %w", collection, err)
		}
		if code != 0 {
			_ = initContainer.Terminate(ctx)
			return nil, func() {}, fmt.Errorf("failed installing %s: exit code %d", collection, code)
		}
	}

	// allow the container some slack before shutting it down again
	time.Sleep(1 * time.Second)

	duration := 3 * time.Second
	if err := initContainer.Stop(ctx, &duration); err != nil {
		return nil, func() {}, fmt.Errorf("failed stopping AppSec init container: %w", err)
	}
	if err := initContainer.Terminate(ctx); err != nil {
		return nil, func() {}, fmt.Errorf("failed terminating AppSec init container: %w", err)
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        containerImage,
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
					Reader:            bytes.NewBufferString(appSecConfig),
					ContainerFilePath: "/etc/crowdsec/acquis.d/appsec.yaml",
				},
			},
		},
		Started: true,
		Logger:  logger,
	})
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed starting AppSec container: %w", err)
	}

	terminate := terminateFunc(c, etcVolume, dataVolume)

	endpointPort, err := c.MappedPort(ctx, "8080/tcp")
	if err != nil {
		terminate()
		return nil, func() {}, fmt.Errorf("failed determining mapped LAPI port: %w", err)
	}

	appsecPort, err := c.MappedPort(ctx, "7422/tcp")
	if err != nil {
		terminate()
		return nil, func() {}, fmt.Errorf("failed determining mapped AppSec port: %w", err)
	}

	return &Container{
		c:        c,
		endpoint: fmt.Sprintf("http://127.0.0.1:%s", endpointPort.Port()),
		appsec:   fmt.Sprintf("http://127.0.0.1:%s", appsecPort.Port()),
	}, terminate, nil
}

// terminateFunc returns a function that terminates c, removing the named
// volumes along with it.
func terminateFunc(c testcontainers.Container, volumes ...string) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		opts := []testcontainers.TerminateOption{}
		if len(volumes) > 0 {
			opts = append(opts, testcontainers.RemoveVolumes(volumes...))
		}

		_ = c.Terminate(ctx, opts...)
	}
}

func randomSuffix() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed generating random suffix: %w", err)
	}

	return hex.EncodeToString(b), nil
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
