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
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"go.uber.org/zap"
)

// New creates a new (streaming) Bouncer with a storage based on immutable radix tree
func New(apiKey, apiURL, tickerInterval string, logger *zap.Logger) (*Bouncer, error) {
	return &Bouncer{
		streamingBouncer: &csbouncer.StreamBouncer{
			APIKey:         apiKey,
			APIUrl:         apiURL,
			TickerInterval: tickerInterval,
			UserAgent:      "caddy-cs-bouncer/v0.1.0",
		},
		store:  newStore(),
		logger: logger,
	}, nil
}

// Bouncer is a custom CrowdSec bouncer backed by an immutable radix tree
type Bouncer struct {
	streamingBouncer *csbouncer.StreamBouncer
	store            *crowdSecStore
	logger           *zap.Logger
}

// Init initializes the Bouncer
func (b *Bouncer) Init() error {
	return b.streamingBouncer.Init()
}

// Run starts the Bouncer processes
func (b *Bouncer) Run() {

	// TODO: handle errors? Return it to caller?

	go func() error {
		b.logger.Info("start processing new and deleted decisions ...")
		for {
			select {
			// TODO: handle the process quitting
			// case <-t.Dying():
			// 	c.logger.Info("terminating bouncer process")
			// 	return nil
			case decisions := <-b.streamingBouncer.Stream:
				b.logger.Debug(fmt.Sprintf("processing %d deleted decisions", len(decisions.Deleted)))
				// TODO: deletions seem to include all old decisions that had already expired; CrowdSec bug or intended behavior?
				for _, decision := range decisions.Deleted {
					if err := b.Delete(decision); err != nil {
						b.logger.Error(fmt.Sprintf("unable to delete decision for '%s': %s", *decision.Value, err))
					} else {
						b.logger.Debug(fmt.Sprintf("deleted '%s'", *decision.Value))
					}
				}
				b.logger.Debug(fmt.Sprintf("processing %d added decisions", len(decisions.New)))
				for _, decision := range decisions.New {
					if err := b.Add(decision); err != nil {
						b.logger.Error(fmt.Sprintf("unable to insert decision for '%s': %s", *decision.Value, err))
					} else {
						b.logger.Debug(fmt.Sprintf("Adding '%s' for '%s'", *decision.Value, *decision.Duration))
					}
				}
			}
		}
	}()

	// TODO: handle connection errors in here? Soft or hard fail? Reconnects?
	go b.streamingBouncer.Run()
}

// ShutDown stops the Bouncer
func (b *Bouncer) ShutDown() error {
	// TODO: persist the current state of the radix tree in some way, so that it can be used in startup again?
	b.store = nil
	return nil
}

// Add adds a Decision to the storage
func (b *Bouncer) Add(decision *models.Decision) error {

	// TODO: provide additional ways for storing the decisions
	// (i.e. radix tree is not always the most efficient one, but it's great for matching IPs to ranges)
	// Knowing that a key is a CIDR does allow to check an IP with the .Contains() function, but still
	// requires looping through the ranges

	// TODO: store additional data about the decision (i.e. time added to store, etc)

	return b.store.add(decision)
}

// Delete removes a Decision from the storage
func (b *Bouncer) Delete(decision *models.Decision) error {
	return b.store.delete(decision)
}

// IsAllowed checks if an IP is allowed or not
func (b *Bouncer) IsAllowed(ip net.IP) (bool, *models.Decision, error) {

	// TODO: perform lookup in explicit allowlist as a kind of quick lookup in front of the CrowdSec lookup list?

	isAllowed := false
	decision, err := b.store.get(ip)
	if err != nil {
		return isAllowed, nil, err // fail closed
	}

	if decision != nil {
		return isAllowed, decision, nil
	}

	// At this point we've determined the IP is allowed
	isAllowed = true

	return isAllowed, decision, nil
}
