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

package crowdsec

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	//httpcaddyfile.RegisterHandlerDirective("crowdsec", parseCaddyfile)
}

// Handler is a Caddy HTTP handler that integrates with the CrowdSec Caddy app
type Handler struct {
	logger   *zap.Logger
	crowdsec *CrowdSec
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.crowdsec",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the OpenAPI Validator responder.
func (h *Handler) Provision(ctx caddy.Context) error {

	crowdsecAppIface, err := ctx.App("crowdsec")
	if err != nil {
		return fmt.Errorf("getting crowdsec app: %v", err)
	}
	h.crowdsec = crowdsecAppIface.(*CrowdSec)

	fmt.Println(h.crowdsec)

	h.logger = ctx.Logger(h)
	defer h.logger.Sync()

	return nil
}

// Validate ensures the app's configuration is valid.
func (h *Handler) Validate() error {
	return nil
}

// ServeHTTP is the Caddy handler for serving HTTP requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	ipToCheck, err := findIPFromRequest(r)
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
			h.logger.Debug("serving ban response")
			return writeBanResponse(w)
		case "captcha":
			h.logger.Debug("serving captcha (ban) response")
			return writeCaptchaResponse(w)
		case "throttle":
			h.logger.Debug("serving throttle response")
			return writeThrottleResponse(w, *decision.Duration)
		default:
			h.logger.Warn(fmt.Sprintf("got crowdsec decision type: %s", typ))
			h.logger.Debug("serving ban response")
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

func writeBanResponse(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusForbidden)
	return nil
}

func writeCaptchaResponse(w http.ResponseWriter) error {
	// TODO: implement showing a captcha in some way. How? hCaptcha? And how to handle afterwards?
	return writeBanResponse(w)
}

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

// findIPFromRequest return client's real public IP address from http request headers.
// Logic largely taken from https://github.com/tomasen/realip/blob/master/realip.go
func findIPFromRequest(r *http.Request) (net.IP, error) {

	// TODO: should we also check X-Real-IP? If so, add it again.
	// TODO: add configuration for custom headers?

	xForwardedFor := r.Header.Get("X-Forwarded-For")

	// If empty, return IP from remote address
	if xForwardedFor == "" {
		var remoteIP string
		var err error
		if strings.ContainsRune(r.RemoteAddr, ':') {
			remoteIP, _, err = net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return nil, err
			}
		} else {
			remoteIP = r.RemoteAddr
		}

		nip := net.ParseIP(remoteIP)
		if nip == nil {
			return nil, fmt.Errorf("could not parse %s into ip", remoteIP)
		}

		return nip, nil
	}

	// Check list of IP in X-Forwarded-For and return the first global address
	for _, address := range strings.Split(xForwardedFor, ",") {
		address = strings.TrimSpace(address)

		// TODO: do additional checks here for right IP to use

		// isPrivate, err := isPrivateAddress(address)
		// if !isPrivate && err == nil {
		// 	return address
		// }
		// if err == nil {
		// 	return address
		// }

		nip := net.ParseIP(address)
		if nip == nil {
			return nil, fmt.Errorf("could not parse %s into ip", address)
		}

		return nip, nil
	}

	return nil, fmt.Errorf("no ip found")
}

// Interface guards
var (
	_ caddy.Module      = (*Handler)(nil)
	_ caddy.Provisioner = (*Handler)(nil)
	_ caddy.Validator   = (*Handler)(nil)
)
