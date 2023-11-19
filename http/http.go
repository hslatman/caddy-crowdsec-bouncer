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
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("crowdsec", parseCaddyfileHandlerDirective)
}

// Handler matches request IPs to CrowdSec decisions to (dis)allow access
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
	ipToCheck, err := determineIPFromRequest(r)
	if err != nil {
		return err // TODO: return error here? Or just log it and continue serving
	}

	isAllowed, decision, err := h.crowdsec.IsAllowed(ipToCheck)
	if err != nil {
		return err // TODO: return error here? Or just log it and continue serving
	}

	if !isAllowed {
		// TODO: maybe some configuration to override the type of action with a ban, some default, something like that?
		// TODO: can we provide the reason for the response to the Caddy logger, like the CrowdSec type, duration, etc.
		typ := *decision.Type
		switch typ {
		case "ban":
			h.logger.Debug(fmt.Sprintf("serving ban response to %s", *decision.Value))
			return writeBanResponse(w)
		case "captcha":
			h.logger.Debug(fmt.Sprintf("serving captcha (ban) response to %s", *decision.Value))
			return writeCaptchaResponse(w)
		case "throttle":
			h.logger.Debug(fmt.Sprintf("serving throttle response to %s", *decision.Value))
			return writeThrottleResponse(w, *decision.Duration)
		default:
			h.logger.Warn(fmt.Sprintf("got crowdsec decision type: %s", typ))
			h.logger.Debug(fmt.Sprintf("serving ban response to %s", *decision.Value))
			return writeBanResponse(w)
		}
	}

	// TODO: if the IP is allowed, should we (temporarily) put it in an explicit allowlist for quicker check?

	// Continue down the handler stack
	err = next.ServeHTTP(w, r)
	if err != nil {
		return err
	}

	return nil
}

// writeBanResponse writes a 403 status as response
func writeBanResponse(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusForbidden)
	return nil
}

// writeCaptchaResponse (currently) writes a 403 status as response
func writeCaptchaResponse(w http.ResponseWriter) error {
	// TODO: implement showing a captcha in some way. How? hCaptcha? And how to handle afterwards?
	return writeBanResponse(w)
}

// writeThrottleResponse writes 429 status as response
func writeThrottleResponse(w http.ResponseWriter, duration string) error {
	d, err := time.ParseDuration(duration)
	if err != nil {
		return err
	}

	// TODO: round this to the nearest multiple of the ticker interval? and/or include the time the decision was processed from stream vs. request time?
	retryAfter := fmt.Sprintf("%.0f", d.Seconds())
	w.Header().Add("Retry-After", retryAfter)
	w.WriteHeader(http.StatusTooManyRequests)

	return nil
}

// determineIPFromRequest returns the IP of the client based on the value that
// Caddy extracts from the original request and stores in the request context.
// Support for setting the real client IP in case a proxy sits in front of
// Caddy was added, so the client IP reported here is the actual client IP.
func determineIPFromRequest(r *http.Request) (net.IP, error) {
	clientIPVar := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey)
	if clientIPVar == nil {
		return nil, errors.New("failed getting client IP from context")
	}

	var clientIP string
	var ok bool
	if clientIP, ok = clientIPVar.(string); !ok {
		return nil, fmt.Errorf("client IP from request context is invalid type %T", clientIPVar)
	}

	if clientIP == "" {
		return nil, errors.New("client IP from request context is empty")
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil, fmt.Errorf("could not parse %q into net.IP", clientIP)
	}

	return ip, nil
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
