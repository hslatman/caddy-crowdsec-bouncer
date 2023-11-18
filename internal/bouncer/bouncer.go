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
	"context"
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const version = "v0.5.3"
const maxNumberOfDecisionsToLog = 10

// Bouncer is a custom CrowdSec bouncer backed by an immutable radix tree
type Bouncer struct {
	streamingBouncer    *csbouncer.StreamBouncer
	liveBouncer         *csbouncer.LiveBouncer
	store               *crowdSecStore
	logger              *zap.Logger
	useStreamingBouncer bool
	shouldFailHard      bool

	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a new (streaming) Bouncer with a storage based on immutable radix tree
// TODO: take a configuration struct instead, because more options will be added.
func New(apiKey, apiURL, tickerInterval string, logger *zap.Logger) (*Bouncer, error) {
	userAgent := fmt.Sprintf("caddy-cs-bouncer/%s", version)
	insecureSkipVerify := false
	return &Bouncer{
		streamingBouncer: &csbouncer.StreamBouncer{
			APIKey:              apiKey,
			APIUrl:              apiURL,
			InsecureSkipVerify:  &insecureSkipVerify,
			TickerInterval:      tickerInterval,
			UserAgent:           userAgent,
			RetryInitialConnect: true,
		},
		liveBouncer: &csbouncer.LiveBouncer{
			APIKey:             apiKey,
			APIUrl:             apiURL,
			InsecureSkipVerify: &insecureSkipVerify,
			UserAgent:          userAgent,
		},
		store:  newStore(),
		logger: logger,
	}, nil
}

// EnableStreaming enables usage of the StreamBouncer (instead of the LiveBouncer).
func (b *Bouncer) EnableStreaming() {
	b.useStreamingBouncer = true
}

// EnableHardFails will make the bouncer fail hard on (connection) errors
// when contacting the CrowdSec Local API.
func (b *Bouncer) EnableHardFails() {
	b.shouldFailHard = true
	b.streamingBouncer.RetryInitialConnect = false
}

// Init initializes the Bouncer
func (b *Bouncer) Init() error {
	// override CrowdSec's default logrus logging
	b.overrideLogrusLogger()

	// initialize the CrowdSec streaming bouncer
	if b.useStreamingBouncer {
		return b.streamingBouncer.Init()
	}

	// initialize the CrowdSec live bouncer
	return b.liveBouncer.Init()
}

// Run starts the Bouncer processes
func (b *Bouncer) Run() {
	// the LiveBouncer has nothing to run in the background; return early
	if !b.useStreamingBouncer {
		return
	}

	// TODO: pass context from top, so that it can influence the running
	// bouncer, and possibly reload/restart it?
	b.ctx, b.cancel = context.WithCancel(context.Background())
	go func() {
		b.streamingBouncer.Run(b.ctx)
	}()

	// TODO: close the stream nicely when the bouncer needs to quit. This is not done
	// in the csbouncer package itself when canceling.
	// TODO: wait with processing until we know we're successfully connected to
	// the CrowdSec API? The bouncer/client doesn't seem to give us that information
	// directly, but we could use the heartbeat service before starting to run?
	// That can also be useful for testing the LiveBouncer at startup.

	go func() {
		for {
			select {
			case <-b.ctx.Done():
				b.logger.Info("processing new and deleted decisions stopped")
				return
			case decisions := <-b.streamingBouncer.Stream:
				if decisions == nil {
					continue
				}
				// TODO: deletions seem to include all old decisions that had already expired; CrowdSec bug or intended behavior?
				// TODO: process in separate goroutines/waitgroup?
				if numberOfDeletedDecisions := len(decisions.Deleted); numberOfDeletedDecisions > 0 {
					b.logger.Debug(fmt.Sprintf("processing %d deleted decisions", numberOfDeletedDecisions))
					for _, decision := range decisions.Deleted {
						if err := b.delete(decision); err != nil {
							b.logger.Error(fmt.Sprintf("unable to delete decision for %q: %s", *decision.Value, err))
						} else {
							if numberOfDeletedDecisions <= maxNumberOfDecisionsToLog {
								b.logger.Debug(fmt.Sprintf("deleted %q (scope: %s)", *decision.Value, *decision.Scope))
							}
						}
					}
					if numberOfDeletedDecisions > maxNumberOfDecisionsToLog {
						b.logger.Debug(fmt.Sprintf("skipped logging for %d deleted decisions", numberOfDeletedDecisions))
					}
					b.logger.Debug(fmt.Sprintf("finished processing %d deleted decisions", numberOfDeletedDecisions))
				}

				// TODO: process in separate goroutines/waitgroup?
				if numberOfNewDecisions := len(decisions.New); numberOfNewDecisions > 0 {
					b.logger.Debug(fmt.Sprintf("processing %d new decisions", numberOfNewDecisions))
					for _, decision := range decisions.New {
						if err := b.add(decision); err != nil {
							b.logger.Error(fmt.Sprintf("unable to insert decision for %q: %s", *decision.Value, err))
						} else {
							if numberOfNewDecisions <= maxNumberOfDecisionsToLog {
								b.logger.Debug(fmt.Sprintf("adding %q (scope: %s) for %q", *decision.Value, *decision.Scope, *decision.Duration))
							}
						}
					}
					if numberOfNewDecisions > maxNumberOfDecisionsToLog {
						b.logger.Debug(fmt.Sprintf("skipped logging for %d new decisions", numberOfNewDecisions))
					}
					b.logger.Debug(fmt.Sprintf("finished processing %d new decisions", numberOfNewDecisions))
				}
			}
		}
	}()
}

// Shutdown stops the Bouncer
func (b *Bouncer) Shutdown() error {
	b.cancel()
	// TODO: clean shutdown of the streaming bouncer channel reading
	//b.store = nil // TODO(hs): setting this to nil without reinstantiating it, leads to errors; do this properly.
	return nil
}

// Add adds a Decision to the storage
func (b *Bouncer) add(decision *models.Decision) error {

	// TODO: provide additional ways for storing the decisions
	// (i.e. radix tree is not always the most efficient one, but it's great for matching IPs to ranges)
	// Knowing that a key is a CIDR does allow to check an IP with the .Contains() function, but still
	// requires looping through the ranges

	// TODO: store additional data about the decision (i.e. time added to store, etc)
	// TODO: wrap the *models.Decision in an internal model (after validation)?

	return b.store.add(decision)
}

// Delete removes a Decision from the storage
func (b *Bouncer) delete(decision *models.Decision) error {
	return b.store.delete(decision)
}

// IsAllowed checks if an IP is allowed or not
func (b *Bouncer) IsAllowed(ip net.IP) (bool, *models.Decision, error) {

	// TODO: perform lookup in explicit allowlist as a kind of quick lookup in front of the CrowdSec lookup list?
	isAllowed := false
	decision, err := b.retrieveDecision(ip)
	if err != nil {
		return isAllowed, nil, err // fail closed
	}

	if decision != nil {
		return isAllowed, decision, nil
	}

	// At this point we've determined the IP is allowed
	isAllowed = true

	return isAllowed, nil, nil
}

func (b *Bouncer) retrieveDecision(ip net.IP) (*models.Decision, error) {
	if b.useStreamingBouncer {
		return b.store.get(ip)
	}

	decision, err := b.liveBouncer.Get(ip.String())
	if err != nil {
		fields := []zapcore.Field{
			zap.String("address", b.streamingBouncer.APIUrl),
			zap.Error(err),
		}
		if b.shouldFailHard {
			b.logger.Fatal(err.Error(), fields...)
		} else {
			b.logger.Error(err.Error(), fields...)
		}
		return nil, nil // when not failing hard, we return no error
	}

	if len(*decision) >= 1 {
		return (*decision)[0], nil // TODO: decide if choosing the first decision is OK
	}

	return nil, nil
}
