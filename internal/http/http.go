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
	"fmt"
	"net/http"

	"github.com/hslatman/caddy-cs-bouncer/internal/app"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CrowdSecHandler{})
	//httpcaddyfile.RegisterHandlerDirective("crowdsec_handler", parseCaddyfile)
}

// CrowdSecHandler is a Caddy HTTP handler that integrates with the CrowdSec Caddy app
type CrowdSecHandler struct {
	logger   *zap.Logger
	crowdsec *app.CrowdSec
}

// CaddyModule returns the Caddy module information.
func (CrowdSecHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.crowdsec",
		New: func() caddy.Module { return new(CrowdSecHandler) },
	}
}

// Provision sets up the OpenAPI Validator responder.
func (ch *CrowdSecHandler) Provision(ctx caddy.Context) error {

	// store some references
	crowdsecAppIface, err := ctx.App("crowdsec")
	if err != nil {
		return fmt.Errorf("getting crowdsec app: %v", err)
	}
	ch.crowdsec = crowdsecAppIface.(*app.CrowdSec)

	fmt.Println(ch.crowdsec)

	ch.logger = ctx.Logger(ch)
	defer ch.logger.Sync()

	return nil
}

// Validate ensures the app's configuration is valid.
func (ch *CrowdSecHandler) Validate() error {
	return nil
}

// ServeHTTP is the Caddy handler for serving HTTP requests
func (ch *CrowdSecHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// TODO: check incoming IP is allowed by making the ch.crowdsec app validate it

	// Continue down the handler stack, recording the response, so that we can work with it afterwards
	err := next.ServeHTTP(w, r)
	if err != nil {
		return err
	}

	return nil
}

// Interface guards
var (
	_ caddy.Module      = (*CrowdSecHandler)(nil)
	_ caddy.Provisioner = (*CrowdSecHandler)(nil)
	_ caddy.Validator   = (*CrowdSecHandler)(nil)
)
