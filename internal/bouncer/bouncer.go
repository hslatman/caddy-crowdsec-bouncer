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

package bouncer

import (
	"encoding/json"
	"fmt"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	iradix "github.com/hashicorp/go-immutable-radix"
	"go.uber.org/zap"
)

func New(apiKey, apiURL, tickerInterval string, logger *zap.Logger) (*Bouncer, error) {
	return &Bouncer{
		streamingBouncer: &csbouncer.StreamBouncer{
			APIKey:         apiKey,
			APIUrl:         apiURL,
			TickerInterval: tickerInterval,
			UserAgent:      "caddy-cs-bouncer",
		},
		store:  iradix.New(),
		logger: logger,
	}, nil
}

type Bouncer struct {
	streamingBouncer *csbouncer.StreamBouncer
	store            *iradix.Tree
	logger           *zap.Logger
}

func (b *Bouncer) Init() error {
	return b.streamingBouncer.Init()
}

func (b *Bouncer) Run() {

	// TODO: handle the error? Return it to caller?

	go func() error {
		b.logger.Debug("Processing new and deleted decisions . . .")
		for {
			select {
			// case <-t.Dying():
			// 	c.logger.Info("terminating bouncer process")
			// 	return nil

			// TODO: decisions should go into some kind of storage
			// The storage can then be used by the HTTP handler to allow/deny the request

			case decisions := <-b.streamingBouncer.Stream:
				b.logger.Debug("got decision ...")
				fmt.Println(decisions)
				//c.logger.Info("deleting '%d' decisions", len(decisions.Deleted))
				for _, decision := range decisions.Deleted {
					if err := b.Delete(decision); err != nil {
						//c.logger.Error("unable to delete decision for '%s': %s", *decision.Value, err)
					} else {
						//c.logger.Debug("deleted '%s'", *decision.Value)
					}

				}
				//c.logger.Info("adding '%d' decisions", len(decisions.New))
				for _, decision := range decisions.New {
					if err := b.Add(decision); err != nil {
						//c.logger.Error("unable to insert decision for '%s': %s", *decision.Value, err)
					} else {
						//c.logger.Debug("Adding '%s' for '%s'", *decision.Value, *decision.Duration)
					}
				}
			}
		}
	}()

	go b.streamingBouncer.Run()
}

func (b *Bouncer) Add(decision *models.Decision) error {
	b.logger.Info("adding ...")
	// banDuration, err := time.ParseDuration(*decision.Duration)
	// if err != nil {
	// 	return err
	// }
	// b.logger.Info("custom [%s] : add ban on %s for %s sec (%s)", c.path, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)

	// str, err := serializeDecision(decision)
	// if err != nil {
	// 	b.logger.Warning("serialize: %s", err)
	// }
	// cmd := exec.Command(c.path, "add", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario, str)
	// if out, err := cmd.CombinedOutput(); err != nil {
	// 	b.logger.Info("Error in 'add' command (%s): %v --> %s", cmd.String(), err, string(out))
	// }
	return nil
}

func (b *Bouncer) Delete(decision *models.Decision) error {
	b.logger.Info("deleting ...")
	// banDuration, err := time.ParseDuration(*decision.Duration)
	// if err != nil {
	// 	return err
	// }

	// str, err := serializeDecision(decision)
	// if err != nil {
	// 	b.logger.Warning("serialize: %s", err)
	// }
	// b.logger.Info("custom [%s] : del ban on %s for %s sec (%s)", c.path, *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario)
	// cmd := exec.Command(c.path, "del", *decision.Value, strconv.Itoa(int(banDuration.Seconds())), *decision.Scenario, str)
	// if out, err := cmd.CombinedOutput(); err != nil {
	// 	b.logger.Info("Error in 'del' command (%s): %v --> %s", cmd.String(), err, string(out))
	// }
	return nil
}

func (b *Bouncer) ShutDown() error {
	return nil
}

func serializeDecision(decision *models.Decision) (string, error) {
	serbyte, err := json.Marshal(decision)
	if err != nil {
		return "", fmt.Errorf("serialize error : %s", err)
	}
	return string(serbyte), nil
}
