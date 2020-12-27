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

package app

import (
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"github.com/hslatman/caddy-cs-bouncer/internal/bouncer"
)

func init() {
	caddy.RegisterModule(Crowdsec{})
	//httpcaddyfile.RegisterHandlerDirective("crowdsec_handler", parseCaddyfile)
}

// CaddyModule returns the Caddy module information.
func (Crowdsec) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "crowdsec",
		New: func() caddy.Module { return new(Crowdsec) },
	}
}

type Crowdsec struct {
	ctx    caddy.Context
	logger *zap.Logger
}

// Provision sets up the OpenAPI Validator responder.
func (c *Crowdsec) Provision(ctx caddy.Context) error {

	c.ctx = ctx
	c.logger = ctx.Logger(c)
	defer c.logger.Sync()

	custom, err := bouncer.New(c.logger)
	if err != nil {
		return err
	}

	if err := custom.Init(); err != nil {
		return err
	}

	bnc := &csbouncer.StreamBouncer{
		APIKey:         "<token>",
		APIUrl:         "http://127.0.0.1:8080/",
		TickerInterval: "60s",
		UserAgent:      "testBouncer",
	}

	if err := bnc.Init(); err != nil {
		return err
	}

	go bnc.Run()

	go func() error {
		c.logger.Debug("Processing new and deleted decisions . . .")
		for {
			select {
			// case <-t.Dying():
			// 	c.logger.Info("terminating bouncer process")
			// 	return nil

			// TODO: decisions should go into some kind of storage
			// The storage can then be used by the HTTP handler to allow/deny the request

			case decisions := <-bnc.Stream:
				c.logger.Debug("got decision ...")
				//c.logger.Info("deleting '%d' decisions", len(decisions.Deleted))
				for _, decision := range decisions.Deleted {
					if err := custom.Delete(decision); err != nil {
						//c.logger.Error("unable to delete decision for '%s': %s", *decision.Value, err)
					} else {
						//c.logger.Debug("deleted '%s'", *decision.Value)
					}

				}
				//c.logger.Info("adding '%d' decisions", len(decisions.New))
				for _, decision := range decisions.New {
					if err := custom.Add(decision); err != nil {
						//c.logger.Error("unable to insert decision for '%s': %s", *decision.Value, err)
					} else {
						//c.logger.Debug("Adding '%s' for '%s'", *decision.Value, *decision.Duration)
					}
				}
			}
		}
	}()

	return nil
}

// Validate ensures the app's configuration is valid.
func (c *Crowdsec) Validate() error {
	return nil
}

func (c *Crowdsec) Start() error {

	// TODO: move the bouncer run part here

	return nil
}

func (c *Crowdsec) Stop() error {

	// TODO: move the bouncer stopping part here

	return nil
}

// Interface guards
var (
	_ caddy.Module      = (*Crowdsec)(nil)
	_ caddy.App         = (*Crowdsec)(nil)
	_ caddy.Provisioner = (*Crowdsec)(nil)
	_ caddy.Validator   = (*Crowdsec)(nil)
)
