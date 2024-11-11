// Copyright 2020 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package layer4

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	l4 "github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Matcher{})
}

// Matcher matches IPs to CrowdSec decisions to (dis)allow access
type Matcher struct {
	logger   *zap.Logger
	crowdsec *crowdsec.CrowdSec
}

// CaddyModule returns the Caddy module information.
func (Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.crowdsec",
		New: func() caddy.Module { return new(Matcher) },
	}
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *Matcher) Provision(ctx caddy.Context) error {
	crowdsecAppIface, err := ctx.App("crowdsec")
	if err != nil {
		return fmt.Errorf("getting crowdsec app: %v", err)
	}
	m.crowdsec = crowdsecAppIface.(*crowdsec.CrowdSec)

	m.logger = ctx.Logger(m)
	defer m.logger.Sync() // nolint

	return nil
}

// Validate ensures the app's configuration is valid.
func (m *Matcher) Validate() error {
	return nil
}

// Match returns true if the connection is from an IP that is
// not denied according to CrowdSec decisions stored in the
// CrowdSec app module.
func (m Matcher) Match(cx *l4.Connection) (bool, error) {

	// TODO: needs to be tested with TCP as well as UDP.

	clientIP, err := m.getClientIP(cx)
	if err != nil {
		return false, err
	}

	isAllowed, _, err := m.crowdsec.IsAllowed(clientIP)
	if err != nil {
		return false, err
	}

	if !isAllowed {
		m.logger.Debug(fmt.Sprintf("connection from %s not allowed", clientIP.String()))
		return false, nil
	}

	return true, nil
}

// getClientIP determines the IP of the client connecting
// Implementation taken from github.com/mholt/caddy-l4/layer4/matchers.go
func (m Matcher) getClientIP(cx *l4.Connection) (netip.Addr, error) {
	remote := cx.Conn.RemoteAddr().String()
	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid client IP address: %s", ipStr)
	}

	return ip, nil
}

// UnmarshalCaddyfile implements [caddyfile.Unmarshaler].
func (m Matcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// Interface guards
var (
	_ l4.ConnMatcher        = (*Matcher)(nil)
	_ caddy.Provisioner     = (*Matcher)(nil)
	_ caddy.Validator       = (*Matcher)(nil)
	_ caddyfile.Unmarshaler = (Matcher)(Matcher{})
)
