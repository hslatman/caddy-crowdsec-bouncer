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

package http

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	_ "github.com/hslatman/caddy-crowdsec-bouncer/appsec" // always include AppSec module when HTTP is added
	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("crowdsec", parseCaddyfileHandlerDirective)
}

// Handler matches request IPs to CrowdSec decisions to (dis)allow access.
type Handler struct {
	logger   *zap.Logger
	crowdsec *crowdsec.CrowdSec
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.crowdsec",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the CrowdSec handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	crowdsecAppIface, err := ctx.App("crowdsec")
	if err != nil {
		return fmt.Errorf("getting crowdsec app: %v", err)
	}
	h.crowdsec = crowdsecAppIface.(*crowdsec.CrowdSec)

	h.logger = ctx.Logger(h)

	return nil
}

// Validate ensures the app's configuration is valid.
func (h *Handler) Validate() error {
	if h.crowdsec == nil {
		return errors.New("crowdsec app not available")
	}

	return nil
}

// Cleanup cleans up resources when the module is being stopped.
func (h *Handler) Cleanup() error {
	if h.logger == nil {
		return nil
	}

	_ = h.logger.Sync() // nolint

	return nil
}

// ServeHTTP is the Caddy handler for serving HTTP requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var (
		ctx = r.Context()
		ip  netip.Addr
	)

	ctx, ip = httputils.EnsureIP(ctx)
	isAllowed, decision, err := h.crowdsec.IsAllowed(ip)
	if err != nil {
		return err // TODO: return error here? Or just log it and continue serving
	}

	// TODO: if the IP is allowed, should we (temporarily) put it in an explicit allowlist for quicker check?

	if !isAllowed {
		// TODO: maybe some configuration to override the type of action with a ban, some default, something like that?
		// TODO: can we provide the reason for the response to the Caddy logger, like the CrowdSec type, duration, etc.
		typ := *decision.Type
		value := *decision.Value
		duration := *decision.Duration

		return httputils.WriteResponse(w, h.logger, typ, value, duration, 0)
	}

	// Continue down the handler stack
	if err := next.ServeHTTP(w, r.WithContext(ctx)); err != nil {
		return err
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// parseCaddyfileHandlerDirective parses the `crowdsec` Caddyfile directive
func parseCaddyfileHandlerDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// Interface guards
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
)
