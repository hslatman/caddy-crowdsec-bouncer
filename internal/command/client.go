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
)

type adminClient struct {
	address string
}

func newAdminClient(address, configFile, configAdapter string) (*adminClient, error) {
	adminAddress, err := caddycmd.DetermineAdminAPIAddress(address, nil, configFile, configAdapter)
	if err != nil {
		return nil, fmt.Errorf("failed to determine admin API address: %w", err)
	}

	return &adminClient{
		address: adminAddress,
	}, nil
}

func (c *adminClient) Health() (adminapi.HealthResponse, error) {
	resp, err := caddycmd.AdminAPIRequest(c.address, http.MethodPost, "/crowdsec/health", nil, nil)
	if err != nil {
		return adminapi.HealthResponse{}, fmt.Errorf("failed getting CrowdSec health: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return adminapi.HealthResponse{}, fmt.Errorf("failed reading CrowdSec health: %w", err)
	}

	var s adminapi.HealthResponse
	if err := json.Unmarshal(b, &s); err != nil {
		return adminapi.HealthResponse{}, fmt.Errorf("failed unmarshaling CrowdSec health: %w", err)
	}

	return s, nil
}

func (c *adminClient) Ping() (adminapi.PingResponse, error) {
	resp, err := caddycmd.AdminAPIRequest(c.address, http.MethodPost, "/crowdsec/ping", nil, nil)
	if err != nil {
		return adminapi.PingResponse{}, fmt.Errorf("failed pinging CrowdSec LAPI: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return adminapi.PingResponse{}, fmt.Errorf("failed reading CrowdSec LAPI ping response: %w", err)
	}

	var p adminapi.PingResponse
	if err := json.Unmarshal(b, &p); err != nil {
		return adminapi.PingResponse{}, fmt.Errorf("failed unmarshaling CrowdSec LAPI ping response: %w", err)
	}

	return p, nil
}

func (c *adminClient) Info() (adminapi.InfoResponse, error) {
	resp, err := caddycmd.AdminAPIRequest(c.address, http.MethodPost, "/crowdsec/info", nil, nil)
	if err != nil {
		return adminapi.InfoResponse{}, fmt.Errorf("failed getting CrowdSec info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return adminapi.InfoResponse{}, fmt.Errorf("failed reading CrowdSec info: %w", err)
	}

	var i adminapi.InfoResponse
	if err := json.Unmarshal(b, &i); err != nil {
		return adminapi.InfoResponse{}, fmt.Errorf("failed unmarshaling CrowdSec info: %w", err)
	}

	return i, nil
}

func (c *adminClient) Check(ip netip.Addr, forceLive bool) (adminapi.CheckResponse, error) {
	reqBytes, err := json.Marshal(adminapi.CheckRequest{
		IP:        ip.String(),
		ForceLive: forceLive,
	})
	if err != nil {
		return adminapi.CheckResponse{}, fmt.Errorf("failed marshaling CrowdSec check request: %w", err)
	}

	resp, err := caddycmd.AdminAPIRequest(c.address, http.MethodPost, "/crowdsec/check", nil, bytes.NewReader(reqBytes))
	if err != nil {
		return adminapi.CheckResponse{}, fmt.Errorf("failed getting CrowdSec check response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return adminapi.CheckResponse{}, fmt.Errorf("failed reading CrowdSec check response: %w", err)
	}

	var r adminapi.CheckResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return adminapi.CheckResponse{}, fmt.Errorf("failed unmarshaling CrowdSec check response: %w", err)
	}

	return r, nil
}
