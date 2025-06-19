package crowdsec

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/adminapi"
)

func init() {
	caddy.RegisterModule(adminAPI{})
}

// adminAPI is a module that serves CrowdSec endpoints to retrieve
// runtime information about the CrowdSec remediation component
// built into, and running as part of Caddy.
type adminAPI struct {
	ctx      caddy.Context
	log      *zap.Logger
	crowdsec *CrowdSec
}

// CaddyModule returns the Caddy module information.
func (adminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.crowdsec",
		New: func() caddy.Module { return new(adminAPI) },
	}
}

// Provision sets up the adminAPI module.
func (a *adminAPI) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.log = ctx.Logger(a)

	crowdsec, err := ctx.App("crowdsec")
	if err != nil {
		return fmt.Errorf("getting crowdsec app: %v", err)
	}

	a.crowdsec = crowdsec.(*CrowdSec)

	return nil
}

// adminCrowdSecEndpointBase is the base admin endpoint under which
// all CrowdSec admin endpoints exist.
const adminCrowdSecEndpointBase = "/crowdsec"

func path(p string) string {
	return fmt.Sprintf("%s/%s", adminCrowdSecEndpointBase, p)
}

// Routes returns the admin routes for the CrowdSec app.
func (a *adminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: path("ping"),
			Handler: handlerWithMiddleware(a.handlePing),
		},
		{
			Pattern: path("check"),
			Handler: handlerWithMiddleware(a.handleCheck),
		},
		{
			Pattern: path("info"),
			Handler: handlerWithMiddleware(a.handleInfo),
		},
		{
			Pattern: path("health"),
			Handler: handlerWithMiddleware(a.handleHealth),
		},
	}
}

func handlerWithMiddleware(next caddy.AdminHandlerFunc) caddy.AdminHandlerFunc {
	return requirePost(next)
}

func requirePost(next caddy.AdminHandlerFunc) caddy.AdminHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return nil
		}

		return next(w, r)
	}
}

func (a *adminAPI) handleHealth(w http.ResponseWriter, r *http.Request) error {
	ok := a.crowdsec.Healthy(r.Context())
	b, err := json.Marshal(adminapi.HealthResponse{
		Ok: ok,
	})
	if err != nil {
		return caddyAPIError(http.StatusInternalServerError, fmt.Errorf("failed marshaling CrowdSec health response: %w", err))
	}

	return writeResponse(w, b)
}

func (a *adminAPI) handleCheck(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return caddyAPIError(http.StatusInternalServerError, fmt.Errorf("failed reading check request: %w", err))
	}

	var req adminapi.CheckRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return caddyAPIError(http.StatusBadRequest, fmt.Errorf("failed unmarshaling check request: %w", err))
	}

	ip, err := netip.ParseAddr(req.IP)
	if err != nil {
		return caddyAPIError(http.StatusBadRequest, fmt.Errorf("failed parsing IP %q: %w", req.IP, err))
	}

	// TODO: return decision (details) too, if set?
	// TODO: if live lookup fails due to API error, that should be reflected; it doesn't seem like that, currently?
	var allowed bool
	if req.ForceLive {
		allowed, _, err = a.crowdsec.bouncer.IsAllowed(ip, true)
	} else {
		allowed, _, err = a.crowdsec.IsAllowed(ip)
	}
	if err != nil {
		return caddyAPIError(http.StatusInternalServerError, fmt.Errorf("failed checking IP %q: %w", ip.String(), err))
	}

	b, err := json.Marshal(adminapi.CheckResponse{Blocked: !allowed})
	if err != nil {
		return caddyAPIError(http.StatusInternalServerError, fmt.Errorf("failed marshaling check response: %w", err))
	}

	return writeResponse(w, b)
}

func (a *adminAPI) handleInfo(w http.ResponseWriter, r *http.Request) error {
	b, err := json.Marshal(adminapi.InfoResponse{
		BouncerEnabled:          a.crowdsec.APIUrl != "",
		AppSecEnabled:           a.crowdsec.AppSecUrl != "",
		StreamingEnabled:        a.crowdsec.isStreamingEnabled(),
		ShouldFailHard:          a.crowdsec.shouldFailHard(),
		UserAgent:               a.crowdsec.bouncer.UserAgent(),
		InstanceID:              a.crowdsec.bouncer.InstanceID(),
		Uptime:                  time.Since(a.crowdsec.bouncer.StartedAt()),
		NumberOfActiveDecisions: a.crowdsec.bouncer.NumberOfActiveDecisions(),
	})
	if err != nil {
		return caddyAPIError(http.StatusInternalServerError, fmt.Errorf("failed marshaling CrowdSec status status: %w", err))
	}

	return writeResponse(w, b)
}

func (a *adminAPI) handlePing(w http.ResponseWriter, r *http.Request) error {
	ok := a.crowdsec.Ping(r.Context())
	b, err := json.Marshal(adminapi.PingResponse{
		Ok: ok,
	})
	if err != nil {
		return caddyAPIError(http.StatusInternalServerError, fmt.Errorf("failed marshaling CrowdSec ping response: %w", err))
	}

	return writeResponse(w, b)
}

func writeResponse(w http.ResponseWriter, b []byte) error {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
	return nil
}

func caddyAPIError(statusCode int, err error) error {
	return caddy.APIError{
		HTTPStatus: statusCode,
		Err:        err,
	}
}

// Interface guards
var (
	_ caddy.AdminRouter = (*adminAPI)(nil)
	_ caddy.Provisioner = (*adminAPI)(nil)
)
