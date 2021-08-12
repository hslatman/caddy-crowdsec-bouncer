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
	"strings"
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

// determineIPFromRequest returns the IP of the client based on its RemoteAddr
// property. In case a proxy, a CDN or some other (usually trusted) server sits
// between the client and Caddy, the real IP of the client is different from
// the one recorded here. To get the actual IP of the client, we propose to
// use the https://github.com/kirsch33/realip Caddy module, which can be
// configured to replace the RemoteAddr of the incoming request with a value
// from a header (i.e. the X-Forwarded-For header), resulting in the actual
// client IP being set in the RemoteAddr property. The `realip` handler should
// be configured before this `crowdsec` handler to work as expected.
func determineIPFromRequest(r *http.Request) (net.IP, error) {

	var remoteIP string
	var err error
	if strings.ContainsRune(r.RemoteAddr, ':') {
		// TODO: does this work correctly with (all) IPv6 addresses?
		remoteIP, _, err = net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return nil, err
		}
	} else {
		remoteIP = r.RemoteAddr
	}

	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return nil, fmt.Errorf("could not parse %s into net.IP", remoteIP)
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
