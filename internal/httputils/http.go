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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"go.uber.org/zap"
)

type DecisionData struct {
	Type        string `default: "allow"`
	StatusCode  int `default: 200`
	Duration    string `default: ""`
	Value       string `default: ""`
	Origin      string `default: ""`
	Request     *http.Request `default: nil`
	RawDecision *models.Decision `default: nil`
}

// determineIPFromRequest returns the IP of the client based on the value that
// Caddy extracts from the original request and stores in the request context.
// Support for setting the real client IP in case a proxy sits in front of
// Caddy was added, so the client IP reported here is the actual client IP.
func determineIPFromRequest(ctx context.Context) (netip.Addr, error) {
	zero := netip.Addr{}
	clientIPVar := caddyhttp.GetVar(ctx, caddyhttp.ClientIPVarKey)
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

// WriteResponse writes a response to the [http.ResponseWriter] based on the Decision object provided.
func WriteResponse(w http.ResponseWriter, logger *zap.Logger, data *DecisionData, useCaddyError bool) error {
	if data == nil {
		return nil
	}
	var message string
	if data.RawDecision != nil {
		message = fmt.Sprintf("CrowdSec issued %s decision (ID %d)", data.Type, data.RawDecision.ID)
	} else {
		message = fmt.Sprintf("CrowdSec issued %s decision", data.Type)
	}
	dataWithoutRequest := *data
	dataWithoutRequest.Request = nil
	dataWithoutRequest.RawDecision = nil
	logger.Info(message, zap.Any("details", dataWithoutRequest))
	if data.RawDecision != nil {
		logger.Debug("Raw decision data for the previous action", zap.Any("request", data.RawDecision))
	} else {
		if data.Request != nil {
			logger.Debug(
				"Reqest data for the previous action",
			    zap.String("method", data.Request.Method),
				zap.String("proto", data.Request.Proto),
			    zap.String("url", data.Request.URL.String()),
				zap.String("host", data.Request.Host),
			    zap.String("remote_addr", data.Request.RemoteAddr),
			    zap.Int64("content_length", data.Request.ContentLength),
				zap.Any("form", data.Request.Form),
			    zap.Any("headers", data.Request.Header),
			)
		}
	}

	switch data.Type {
		case "captcha":
			return writeCaptchaResponse(w, data.StatusCode, useCaddyError, message)
		case "throttle":
			return writeThrottleResponse(w,  data.Duration, useCaddyError, message)
		default:
			return writeBanResponse(w, data.StatusCode, useCaddyError, message)
	}
}

// writeBanResponse writes a 403 status as response
func writeBanResponse(w http.ResponseWriter, statusCode int, useCaddyError bool, message string) error {
	code := statusCode
	if code <= 0 {
		code = http.StatusForbidden
	}
	if useCaddyError {
		return caddyhttp.Error(code, errors.New(message))
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	return nil
}

// writeCaptchaResponse (currently) writes a 403 status as response
func writeCaptchaResponse(w http.ResponseWriter, statusCode int, useCaddyError bool, message string) error {
	// TODO: implement showing a captcha in some way. How? hCaptcha? And how to handle afterwards?
	return writeBanResponse(w, statusCode, useCaddyError, message)
}

// writeThrottleResponse writes 429 status as response
func writeThrottleResponse(w http.ResponseWriter, duration string, useCaddyError bool, message string) error {
	d, err := time.ParseDuration(duration)
	if err != nil {
		return err
	}

	// TODO: round this to the nearest multiple of the ticker interval? and/or include the time the decision was processed from stream vs. request time?
	retryAfter := fmt.Sprintf("%.0f", d.Seconds())
	w.Header().Add("Retry-After", retryAfter)

	if useCaddyError {
		return caddyhttp.Error(http.StatusTooManyRequests, errors.New(message))
	}
	w.WriteHeader(http.StatusTooManyRequests)
	return nil
}
