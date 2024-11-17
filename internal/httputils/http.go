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

package httputils

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// determineIPFromRequest returns the IP of the client based on the value that
// Caddy extracts from the original request and stores in the request context.
// Support for setting the real client IP in case a proxy sits in front of
// Caddy was added, so the client IP reported here is the actual client IP.
func determineIPFromRequest(r *http.Request) (netip.Addr, error) {
	zero := netip.Addr{}
	clientIPVar := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey)
	if clientIPVar == nil {
		return zero, errors.New("failed getting client IP from context")
	}

	var clientIP string
	var ok bool
	if clientIP, ok = clientIPVar.(string); !ok {
		return zero, fmt.Errorf("client IP from request context is invalid type %T", clientIPVar)
	}

	if clientIP == "" {
		return zero, errors.New("client IP from request context is empty")
	}

	ip, err := netip.ParseAddr(clientIP)
	if err != nil {
		return zero, fmt.Errorf("could not parse %q into netip.Addr", clientIP)
	}

	return ip, nil
}

// WriteResponse writes a response to the [http.ResponseWriter] based on the typ, value,
// duration and status code provide.
func WriteResponse(w http.ResponseWriter, logger *zap.Logger, typ, value, duration string, statusCode int) error {
	switch typ {
	case "ban":
		logger.Debug(fmt.Sprintf("serving ban response to %s", value))
		return writeBanResponse(w, statusCode)
	case "captcha":
		logger.Debug(fmt.Sprintf("serving captcha (ban) response to %s", value))
		return writeCaptchaResponse(w, statusCode)
	case "throttle":
		logger.Debug(fmt.Sprintf("serving throttle response to %s", value))
		return writeThrottleResponse(w, duration)
	default:
		logger.Warn(fmt.Sprintf("got crowdsec decision type: %s", typ))
		logger.Debug(fmt.Sprintf("serving ban response to %s", value))
		return writeBanResponse(w, statusCode)
	}
}

// writeBanResponse writes a 403 status as response
func writeBanResponse(w http.ResponseWriter, statusCode int) error {
	code := statusCode
	if code <= 0 {
		code = http.StatusForbidden
	}

	w.WriteHeader(code)
	return nil
}

// writeCaptchaResponse (currently) writes a 403 status as response
func writeCaptchaResponse(w http.ResponseWriter, statusCode int) error {
	// TODO: implement showing a captcha in some way. How? hCaptcha? And how to handle afterwards?
	return writeBanResponse(w, statusCode)
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
