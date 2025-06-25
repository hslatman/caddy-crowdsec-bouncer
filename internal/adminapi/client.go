package adminapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/google/uuid"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/version"
)

const (
	UserAgentName = "caddy-crowdsec-cmd"
)

type Client struct {
	address   string
	userAgent string
}

type ClientConfig struct {
	Address    string
	ConfigFile string
	Adapter    string
}

func NewClient(cfg ClientConfig) (*Client, error) {
	adminAddress, err := caddycmd.DetermineAdminAPIAddress(cfg.Address, nil, cfg.ConfigFile, cfg.Adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to determine admin API address: %w", err)
	}

	userAgentVersion := version.Current()
	userAgent := UserAgentName + "/" + userAgentVersion

	return &Client{
		address:   adminAddress,
		userAgent: userAgent,
	}, nil
}

func (c *Client) doRequest(path string, body io.Reader) ([]byte, error) {
	resp, err := caddycmd.AdminAPIRequest(c.address, http.MethodPost, path, c.headers(), body)
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

func (c *Client) headers() http.Header {
	return http.Header{
		"User-Agent":   []string{c.userAgent},
		"X-Request-ID": []string{uuid.New().String()},
	}
}

func (c *Client) Health() (*HealthResponse, error) {
	b, err := c.doRequest("/crowdsec/health", nil)
	if err != nil {
		return nil, err
	}

	var s HealthResponse
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("failed unmarshaling CrowdSec health: %w", err)
	}

	return &s, nil
}

func (c *Client) Ping() (*PingResponse, error) {
	b, err := c.doRequest("/crowdsec/ping", nil)
	if err != nil {
		return nil, err
	}

	var p PingResponse
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("failed unmarshaling CrowdSec LAPI ping response: %w", err)
	}

	return &p, nil
}

func (c *Client) Info() (*InfoResponse, error) {
	b, err := c.doRequest("/crowdsec/info", nil)
	if err != nil {
		return nil, err
	}

	var i InfoResponse
	if err := json.Unmarshal(b, &i); err != nil {
		return nil, fmt.Errorf("failed unmarshaling CrowdSec info: %w", err)
	}

	return &i, nil
}

func (c *Client) Check(ip netip.Addr, forceLive bool) (*CheckResponse, error) {
	reqBytes, err := json.Marshal(CheckRequest{
		IP:        ip.String(),
		ForceLive: forceLive,
	})
	if err != nil {
		return nil, fmt.Errorf("failed marshaling CrowdSec check request: %w", err)
	}

	b, err := c.doRequest("/crowdsec/check", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}

	var r CheckResponse
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("failed unmarshaling CrowdSec check response: %w", err)
	}

	return &r, nil
}
