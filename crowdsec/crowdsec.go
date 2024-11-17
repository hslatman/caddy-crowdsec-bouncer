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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"go.uber.org/zap"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/bouncer"
)

func init() {
	caddy.RegisterModule(CrowdSec{})
	httpcaddyfile.RegisterGlobalOption("crowdsec", parseCrowdSec)
}

// CaddyModule returns the Caddy module information.
func (CrowdSec) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "crowdsec",
		New: func() caddy.Module { return new(CrowdSec) },
	}
}

// CrowdSec is a Caddy App that functions as a CrowdSec bouncer. It acts
// as a CrowdSec API client as well as a local cache for CrowdSec decisions,
// which can be used by the HTTP handler and Layer4 matcher to decide if
// a request or connection is allowed or not.
type CrowdSec struct {
	// APIUrl for the CrowdSec Local API. Defaults to http://127.0.0.1:8080/.
	APIUrl string `json:"api_url,omitempty"`
	// APIKey for the CrowdSec Local API.
	APIKey string `json:"api_key"`
	// TickerInterval is the interval the StreamBouncer uses for querying
	// the CrowdSec Local API. Defaults to "60s".
	TickerInterval string `json:"ticker_interval,omitempty"`
	// EnableStreaming indicates whether the StreamBouncer should be used.
	// If it's false, the LiveBouncer is used. The StreamBouncer keeps
	// CrowdSec decisions in memory, resulting in quicker lookups. The
	// LiveBouncer will perform an API call to your CrowdSec instance.
	// Defaults to true.
	EnableStreaming *bool `json:"enable_streaming,omitempty"`
	// EnableHardFails indicates whether calls to the CrowdSec API should
	// result in hard failures, resulting in Caddy quitting vs.
	// Caddy continuing operation (with a chance of not performing)
	// validations. Defaults to false.
	EnableHardFails *bool `json:"enable_hard_fails,omitempty"`
	// AppSecUrl is the URL of the AppSec component served by your
	// CrowdSec installation. Disabled by default.
	AppSecUrl string `json:"appsec_url,omitempty"`

	ctx     caddy.Context
	logger  *zap.Logger
	bouncer *bouncer.Bouncer
}

// Provision sets up the CrowdSec app.
func (c *CrowdSec) Provision(ctx caddy.Context) error {
	c.ctx = ctx
	c.logger = ctx.Logger(c)
	defer c.logger.Sync() // nolint

	repl := caddy.NewReplacer() // create replacer with the default, global replacement functions, including ".env" env var reading
	c.APIUrl = repl.ReplaceKnown(c.APIUrl, "")
	c.APIKey = repl.ReplaceKnown(c.APIKey, "")
	c.TickerInterval = repl.ReplaceKnown(c.TickerInterval, "")
	c.AppSecUrl = repl.ReplaceKnown(c.AppSecUrl, "")

	if c.APIUrl == "" {
		c.APIUrl = "http://127.0.0.1:8080/"
	}
	if c.TickerInterval == "" {
		c.TickerInterval = "60s"
	}

	bouncer, err := bouncer.New(c.APIKey, c.APIUrl, c.AppSecUrl, c.TickerInterval, c.logger)
	if err != nil {
		return err
	}

	if c.isStreamingEnabled() {
		bouncer.EnableStreaming()
	}

	if c.shouldFailHard() {
		bouncer.EnableHardFails()
	}

	c.bouncer = bouncer

	return nil
}

// Validate ensures the app's configuration is valid.
func (c *CrowdSec) Validate() error {
	if c.APIKey == "" {
		return errors.New("crowdsec API key must not be empty")
	}
	if c.bouncer == nil {
		return errors.New("bouncer instance not available due to (potential) misconfiguration")
	}
	if err := c.checkModules(); err != nil {
		return fmt.Errorf("failed checking CrowdSec modules: %w", err)
	}

	return nil
}

const (
	appSecHandlerName = "http.handlers.appsec"
	httpHandlerName   = "http.handlers.crowdsec"
	matcherName       = "layer4.matchers.crowdsec"
)

var crowdSecModules = []string{httpHandlerName, appSecHandlerName, matcherName}

func (c *CrowdSec) checkModules() error {
	modules, err := matchModules(crowdSecModules...)
	if err != nil {
		return fmt.Errorf("failed retrieving CrowdSec modules: %w", err)
	}

	layer4, err := matchModules("layer4")
	if err != nil {
		return fmt.Errorf("failed retrieving layer4 module: %w", err)
	}

	hasLayer4 := len(layer4) > 0
	switch {
	case hasLayer4 && len(modules) == 0:
		c.logger.Warn(fmt.Sprintf("%s and %s modules are not available", httpHandlerName, matcherName))
	case hasLayer4 && hasModule(modules, matcherName) && !hasModule(modules, httpHandlerName):
		c.logger.Warn(fmt.Sprintf("%s module is not available", httpHandlerName))
	case hasLayer4 && hasModule(modules, httpHandlerName) && !hasModule(modules, matcherName):
		c.logger.Warn(fmt.Sprintf("%s module is not available", matcherName))
	case len(modules) == 0:
		c.logger.Warn(fmt.Sprintf("%s module is not available", httpHandlerName))
	}

	return nil
}

type moduleInfo struct {
	caddyModuleID string
	standard      bool
	goModule      *debug.Module
	err           error
}

func hasModule(modules []moduleInfo, moduleIdentifier string) bool {
	for _, m := range modules {
		if m.caddyModuleID == moduleIdentifier {
			return true
		}
	}
	return false
}

func matchModules(moduleIdentifiers ...string) (modules []moduleInfo, err error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		err = fmt.Errorf("no build info")
		return
	}

	for _, modID := range caddy.Modules() {
		if !slices.Contains(moduleIdentifiers, modID) {
			continue
		}

		modInfo, err := caddy.GetModule(modID)
		if err != nil {
			modules = append(modules, moduleInfo{caddyModuleID: modID, err: err})
			continue
		}

		// to get the Caddy plugin's version info, we need to know
		// the package that the Caddy module's value comes from; we
		// can use reflection but we need a non-pointer value (I'm
		// not sure why), and since New() should return a pointer
		// value, we need to dereference it first
		iface := any(modInfo.New())
		if rv := reflect.ValueOf(iface); rv.Kind() == reflect.Ptr {
			iface = reflect.New(reflect.TypeOf(iface).Elem()).Elem().Interface()
		}
		modPkgPath := reflect.TypeOf(iface).PkgPath()

		// now we find the Go module that the Caddy module's package
		// belongs to; we assume the Caddy module package path will
		// be prefixed by its Go module path, and we will choose the
		// longest matching prefix in case there are nested modules
		var matched *debug.Module
		for _, dep := range bi.Deps {
			if strings.HasPrefix(modPkgPath, dep.Path) {
				if matched == nil || len(dep.Path) > len(matched.Path) {
					matched = dep
				}
			}
		}

		standard := strings.HasPrefix(modPkgPath, caddy.ImportPath)
		modules = append(modules, moduleInfo{caddyModuleID: modID, standard: standard, goModule: matched})
	}
	return
}

func (c *CrowdSec) Cleanup() error {
	if err := c.bouncer.Shutdown(); err != nil {
		return fmt.Errorf("failed cleaning up: %w", err)
	}

	c.logger.Sync() // nolint

	return nil
}

// Start starts the CrowdSec Caddy app
func (c *CrowdSec) Start() error {
	if err := c.bouncer.Init(); err != nil {
		return err
	}

	c.bouncer.Run(context.Background())

	return nil
}

// Stop stops the CrowdSec Caddy app
func (c *CrowdSec) Stop() error {
	return c.bouncer.Shutdown()
}

// IsAllowed is used by the CrowdSec HTTP handler to check if
// an IP is allowed to perform a request.
func (c *CrowdSec) IsAllowed(ip netip.Addr) (bool, *models.Decision, error) {
	return c.bouncer.IsAllowed(ip)
}

// CheckRequest checks the incoming request against AppSec.
func (c *CrowdSec) CheckRequest(ctx context.Context, r *http.Request) error {
	return c.bouncer.CheckRequest(ctx, r)
}

func (c *CrowdSec) isStreamingEnabled() bool {
	return c.EnableStreaming == nil || *c.EnableStreaming
}

func (c *CrowdSec) shouldFailHard() bool {
	return c.EnableHardFails != nil && *c.EnableHardFails
}

// Interface guards
var (
	_ caddy.Module       = (*CrowdSec)(nil)
	_ caddy.App          = (*CrowdSec)(nil)
	_ caddy.Provisioner  = (*CrowdSec)(nil)
	_ caddy.Validator    = (*CrowdSec)(nil)
	_ caddy.CleanerUpper = (*CrowdSec)(nil)
)
