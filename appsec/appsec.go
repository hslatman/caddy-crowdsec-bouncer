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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("appsec", parseCaddyfileHandlerDirective)
}

// Handler matches request IPs to CrowdSec decisions to (dis)allow access
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

// Provision sets up the CrowdSec handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	crowdsecAppIface, err := ctx.App("crowdsec")
	if err != nil {
		return fmt.Errorf("getting crowdsec app: %v", err)
	}
	h.crowdsec = crowdsecAppIface.(*crowdsec.CrowdSec)

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
	err := h.crowdsec.CheckRequest(r.Context(), r)
	if err != nil {
		// TODO: do something with the error
		// TODO: add (debug) logging
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
