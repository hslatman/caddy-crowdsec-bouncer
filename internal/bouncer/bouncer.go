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
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const version = "v0.6.0"
const maxNumberOfDecisionsToLog = 10

// Bouncer is a wrapper for a CrowdSec bouncer. It supports both the the
// streaming and live bouncer implementations. The streaming bouncer is
// backed by an immutable radix tree storing known bad IPs and IP ranges.
// The live bouncer will reach out to the CrowdSec agent on every check.
type Bouncer struct {
	streamingBouncer    *csbouncer.StreamBouncer
	liveBouncer         *csbouncer.LiveBouncer
	store               *crowdSecStore
	logger              *zap.Logger
	useStreamingBouncer bool
	shouldFailHard      bool
	instantiatedAt      time.Time
	instanceID          string

	ctx     context.Context
	started bool
	stopped bool
	startMu sync.Mutex
	cancel  context.CancelFunc
	wg      *sync.WaitGroup
}

// New creates a new (streaming) Bouncer with a storage based on immutable radix tree
// TODO: take a configuration struct instead, because more options will be added.
func New(apiKey, apiURL, tickerInterval string, logger *zap.Logger) (*Bouncer, error) {
	userAgent := fmt.Sprintf("caddy-cs-bouncer/%s", version)
	insecureSkipVerify := false
	instantiatedAt := time.Now()
	instanceID, err := generateInstanceID(instantiatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed generating instance ID: %w", err)
	}

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
		store:          newStore(),
		logger:         logger,
		instantiatedAt: instantiatedAt,
		instanceID:     instanceID,
	}, nil
}

func generateInstanceID(t time.Time) (string, error) {
	r := rand.New(rand.NewSource(t.Unix()))
	b := [4]byte{}
	if _, err := r.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
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

func (b *Bouncer) zapField() zapcore.Field {
	return zap.String("instance_id", b.instanceID)
}

// Init initializes the Bouncer
func (b *Bouncer) Init() error {
	// override CrowdSec's default logrus logging
	b.overrideLogrusLogger()

	// initialize the CrowdSec live bouncer
	if !b.useStreamingBouncer {
		b.logger.Info("initializing live bouncer", b.zapField())
		return b.liveBouncer.Init()
	}

	// initialize the CrowdSec streaming bouncer
	b.logger.Info("initializing streaming bouncer", b.zapField())
	return b.streamingBouncer.Init()
}

// Run starts the Bouncer processes
func (b *Bouncer) Run() {
	b.startMu.Lock()
	if b.started && !b.stopped {
		return
	}
	b.started = true
	b.startMu.Unlock()

	b.logger.Info("started", b.zapField())

	// the LiveBouncer has nothing to run in the background; return early
	if !b.useStreamingBouncer {
		return
	}

	b.wg = &sync.WaitGroup{}
	b.ctx, b.cancel = context.WithCancel(context.Background())

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.streamingBouncer.Run(b.ctx)
	}()

	// TODO: close the stream nicely when the bouncer needs to quit. This is not done
	// in the csbouncer package itself when canceling.
	// TODO: wait with processing until we know we're successfully connected to
	// the CrowdSec API? The bouncer/client doesn't seem to give us that information
	// directly, but we could use the heartbeat service before starting to run?
	// That can also be useful for testing the LiveBouncer at startup.

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			select {
			case <-b.ctx.Done():
				b.logger.Info("processing new and deleted decisions stopped", b.zapField())
				return
			case decisions := <-b.streamingBouncer.Stream:
				if decisions == nil {
					continue
				}
				// TODO: deletions seem to include all old decisions that had already expired; CrowdSec bug or intended behavior?
				// TODO: process in separate goroutines/waitgroup?
				if numberOfDeletedDecisions := len(decisions.Deleted); numberOfDeletedDecisions > 0 {
					b.logger.Debug(fmt.Sprintf("processing %d deleted decisions", numberOfDeletedDecisions), b.zapField())
					for _, decision := range decisions.Deleted {
						if err := b.delete(decision); err != nil {
							b.logger.Error(fmt.Sprintf("unable to delete decision for %q: %s", *decision.Value, err), b.zapField())
						} else {
							if numberOfDeletedDecisions <= maxNumberOfDecisionsToLog {
								b.logger.Debug(fmt.Sprintf("deleted %q (scope: %s)", *decision.Value, *decision.Scope), b.zapField())
							}
						}
					}
					if numberOfDeletedDecisions > maxNumberOfDecisionsToLog {
						b.logger.Debug(fmt.Sprintf("skipped logging for %d deleted decisions", numberOfDeletedDecisions), b.zapField())
					}
					b.logger.Debug(fmt.Sprintf("finished processing %d deleted decisions", numberOfDeletedDecisions), b.zapField())
				}

				// TODO: process in separate goroutines/waitgroup?
				if numberOfNewDecisions := len(decisions.New); numberOfNewDecisions > 0 {
					b.logger.Debug(fmt.Sprintf("processing %d new decisions", numberOfNewDecisions), b.zapField())
					for _, decision := range decisions.New {
						if err := b.add(decision); err != nil {
							b.logger.Error(fmt.Sprintf("unable to insert decision for %q: %s", *decision.Value, err), b.zapField())
						} else {
							if numberOfNewDecisions <= maxNumberOfDecisionsToLog {
								b.logger.Debug(fmt.Sprintf("adding %q (scope: %s) for %q", *decision.Value, *decision.Scope, *decision.Duration), b.zapField())
							}
						}
					}
					if numberOfNewDecisions > maxNumberOfDecisionsToLog {
						b.logger.Debug(fmt.Sprintf("skipped logging for %d new decisions", numberOfNewDecisions), b.zapField())
					}
					b.logger.Debug(fmt.Sprintf("finished processing %d new decisions", numberOfNewDecisions), b.zapField())
				}
			}
		}
	}()
}

// Shutdown stops the Bouncer
func (b *Bouncer) Shutdown() error {
	b.startMu.Lock()
	defer b.startMu.Unlock()
	if !b.started || b.stopped {
		return nil
	}

	b.logger.Info("stopping", b.zapField())

	// the LiveBouncer has nothing to do on shutdown
	if !b.useStreamingBouncer {
		return nil
	}

	b.cancel()
	b.wg.Wait()

	b.stopped = true
	b.logger.Info("finished", b.zapField())
	b.logger.Sync() // nolint

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
			b.zapField(),
			zap.String("address", b.liveBouncer.APIUrl),
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
