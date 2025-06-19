package command

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/version"
)

const (
	UserAgentName = "caddy-crowdsec-cmd"
)

type adminClient struct {
	address string
	headers http.Header
}

func newAdminClient(fl caddycmd.Flags) (*adminClient, error) {
	adminAddress, err := caddycmd.DetermineAdminAPIAddress(fl.String("address"), nil, fl.String("config"), fl.String("adapter"))
	if err != nil {
		return nil, fmt.Errorf("failed to determine admin API address: %w", err)
	}

	userAgentVersion := version.Current()
	userAgent := UserAgentName + "/" + userAgentVersion

	return &adminClient{
		address: adminAddress,
		headers: http.Header{
			"User-Agent": []string{userAgent},
		},
	}, nil
}

func (c *adminClient) doRequest(path string, body io.Reader) ([]byte, error) {
	resp, err := caddycmd.AdminAPIRequest(c.address, http.MethodPost, path, c.headers, body)
	if err != nil {
		return nil, fmt.Errorf("admin API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading admin API response failed: %w", err)
	}

	return b, nil
}

func (c *adminClient) Health() (*adminapi.HealthResponse, error) {
	b, err := c.doRequest("/crowdsec/health", nil)
	if err != nil {
		return nil, err
	}

	var s adminapi.HealthResponse
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("failed unmarshaling CrowdSec health: %w", err)
	}

	return &s, nil
}

func (c *adminClient) Ping() (*adminapi.PingResponse, error) {
	b, err := c.doRequest("/crowdsec/ping", nil)
	if err != nil {
		return nil, err
	}

	var p adminapi.PingResponse
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("failed unmarshaling CrowdSec LAPI ping response: %w", err)
	}

	return &p, nil
}

func (c *adminClient) Info() (*adminapi.InfoResponse, error) {
	b, err := c.doRequest("/crowdsec/info", nil)
	if err != nil {
		return nil, err
	}

	var i adminapi.InfoResponse
	if err := json.Unmarshal(b, &i); err != nil {
		return nil, fmt.Errorf("failed unmarshaling CrowdSec info: %w", err)
	}

	return &i, nil
}

func (c *adminClient) Check(ip netip.Addr, forceLive bool) (*adminapi.CheckResponse, error) {
	reqBytes, err := json.Marshal(adminapi.CheckRequest{
		IP:        ip.String(),
		ForceLive: forceLive,
	})
	if err != nil {
		return nil, fmt.Errorf("failed marshaling CrowdSec check request: %w", err)
	}

	b, err := c.doRequest("/crowdsec/info", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}

	var r adminapi.CheckResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("failed unmarshaling CrowdSec check response: %w", err)
	}

	return &r, nil
}
