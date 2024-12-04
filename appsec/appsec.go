// Copyright 2024 Herman Slatman
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

package appsec

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

	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/bouncer"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/httputils"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("appsec", parseCaddyfileHandlerDirective)
}

// Handler checks the CrowdSec AppSec component decided whether
// an HTTP request is blocked or not.
type Handler struct {
	logger   *zap.Logger
	crowdsec *crowdsec.CrowdSec
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.appsec",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the CrowdSec AppSec handler.
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
	h.logger.Sync() // nolint

	return nil
}

// ServeHTTP is the Caddy handler for serving HTTP requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var (
		ctx = r.Context()
		ip  netip.Addr
	)

	ctx, ip = httputils.EnsureIP(ctx)
	if err := h.crowdsec.CheckRequest(ctx, r); err != nil {
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
			return httputils.WriteResponse(w, h.logger, a.Action, ip.String(), a.Duration, a.StatusCode)
		}
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
)
