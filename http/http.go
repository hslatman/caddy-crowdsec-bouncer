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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	_ "github.com/hslatman/caddy-crowdsec-bouncer/appsec" // include support for AppSec WAF component
	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/bouncer"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/utils"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("crowdsec", parseCaddyfileHandlerDirective)
}

// Handler matches request IPs to CrowdSec decisions to (dis)allow access
type Handler struct {
	logger        *zap.Logger
	crowdsec      *crowdsec.CrowdSec
	appsecEnabled bool
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

	h.appsecEnabled = true // TODO: make configurable

	h.logger = ctx.Logger(h)
	defer h.logger.Sync() // nolint

	return nil
}

// Validate ensures the app's configuration is valid.
func (h *Handler) Validate() error {

	if h.crowdsec == nil {
		return errors.New("crowdsec app not available")
	}

	return nil
}

// ServeHTTP is the Caddy handler for serving HTTP requests
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip, err := utils.DetermineIPFromRequest(r)
	if err != nil {
		return err // TODO: return error here? Or just log it and continue serving
	}

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

		return utils.WriteResponse(w, h.logger, typ, value, duration, 0)
	}

	if h.appsecEnabled {
		if err := h.crowdsec.CheckRequest(r.Context(), r); err != nil {
			a := &bouncer.AppSecError{}
			if !errors.As(err, &a) {
				return err
			}

			switch a.Action {
			case "allow":
				// nothing to do
			case "log":
				h.logger.Info("appsec rule triggered", zap.String("ip", ip.String()), zap.String("action", a.Action))
			default:
				return utils.WriteResponse(w, h.logger, a.Action, ip.String(), a.Duration, a.StatusCode)
			}
		}
	}

	// Continue down the handler stack
	if err := next.ServeHTTP(w, r); err != nil {
		return err
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// TODO: parse additional handler directives (none exist now)
	return nil
}

// parseCaddyfileHandlerDirective parses the `crowdsec` Caddyfile directive
func parseCaddyfileHandlerDirective(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return handler, err
}

// Interface guards
var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
