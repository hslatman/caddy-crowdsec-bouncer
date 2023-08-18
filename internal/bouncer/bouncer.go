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
	"io"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/sirupsen/logrus"

	"go.uber.org/zap"
)

// Bouncer is a custom CrowdSec bouncer backed by an immutable radix tree
type Bouncer struct {
	streamingBouncer    *csbouncer.StreamBouncer
	liveBouncer         *csbouncer.LiveBouncer
	store               *crowdSecStore
	logger              *zap.Logger
	useStreamingBouncer bool
	shouldFailHard      bool
}

type logrusErrorHook struct {
	fn func(entry *logrus.Entry) error
}

func (lh *logrusErrorHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel}
}

func (lh *logrusErrorHook) Fire(entry *logrus.Entry) error {
	if lh.fn == nil {
		return nil
	}
	return lh.fn(entry)
}

var _ logrus.Hook = (*logrusErrorHook)(nil)

// New creates a new (streaming) Bouncer with a storage based on immutable radix tree
func New(apiKey, apiURL, tickerInterval string, logger *zap.Logger) (*Bouncer, error) {
	userAgent := "caddy-cs-bouncer/v0.3.2"
	insecureSkipVerify := false
	return &Bouncer{
		streamingBouncer: &csbouncer.StreamBouncer{
			APIKey:             apiKey,
			APIUrl:             apiURL,
			InsecureSkipVerify: &insecureSkipVerify,
			TickerInterval:     tickerInterval,
			UserAgent:          userAgent,
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

// EnableStreaming enables usage of the StreamBouncer (instead of the LiveBouncer)
func (b *Bouncer) EnableStreaming() {
	b.useStreamingBouncer = true
}

// EnableHardFails will make the bouncer fail hard on (connection) errors
// when contacting the CrowdSec Local API
func (b *Bouncer) EnableHardFails() {
	b.shouldFailHard = true
}

// Init initializes the Bouncer
func (b *Bouncer) Init() error {

	if b.useStreamingBouncer {
		// silence the default CrowdSec logrus logging
		logrus.SetOutput(io.Discard)

		// catch error log entries and log them using the *zap.Logger instead
		errorHook := &logrusErrorHook{
			fn: func(entry *logrus.Entry) error {
				// TODO: extract from entry.Data? But doesn't seem to be used by CrowdSec today.
				if entry == nil {
					return nil
				}
				msg := entry.Message
				if b.shouldFailHard {
					b.logger.Fatal(msg, zap.String("address", b.streamingBouncer.APIUrl))
				} else {
					b.logger.Error(msg, zap.String("address", b.streamingBouncer.APIUrl))
				}
				return nil
			},
		}
		logrus.AddHook(errorHook)

		// TODO: catch other logrus levels too?

		// initialize the CrowdSec streaming bouncer
		return b.streamingBouncer.Init()
	}

	return b.liveBouncer.Init()
}

// Run starts the Bouncer processes
func (b *Bouncer) Run() {

	if !b.useStreamingBouncer {
		// the LiveBouncer has nothing to run in the background; return early
		return
	}

	go func() {
		b.logger.Info("start processing new and deleted decisions")
		for decisions := range b.streamingBouncer.Stream {
			if len(decisions.Deleted) > 0 {
				b.logger.Debug(fmt.Sprintf("processing %d deleted decisions", len(decisions.Deleted)))
			}
			// TODO: deletions seem to include all old decisions that had already expired; CrowdSec bug or intended behavior?
			// TODO: process in separate goroutines/waitgroup?
			for _, decision := range decisions.Deleted {
				if err := b.delete(decision); err != nil {
					b.logger.Error(fmt.Sprintf("unable to delete decision for '%s': %s", *decision.Value, err))
				} else {
					b.logger.Debug(fmt.Sprintf("deleted '%s' (scope: %s)", *decision.Value, *decision.Scope))
				}
			}
			if len(decisions.New) > 0 {
				b.logger.Debug(fmt.Sprintf("processing %d new decisions", len(decisions.New)))
			}
			// TODO: process in separate goroutines/waitgroup?
			for _, decision := range decisions.New {
				if err := b.add(decision); err != nil {
					b.logger.Error(fmt.Sprintf("unable to insert decision for '%s': %s", *decision.Value, err))
				} else {
					b.logger.Debug(fmt.Sprintf("adding '%s' (scope: %s) for '%s'", *decision.Value, *decision.Scope, *decision.Duration))
				}
			}
		}
	}()

	go b.streamingBouncer.Run(context.Background()) // TODO: pass context from top?
}

// ShutDown stops the Bouncer
func (b *Bouncer) ShutDown() error {
	// TODO: persist the current state of the radix tree in some way, so that it can be used in startup again?
	b.store = nil
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
		if b.shouldFailHard {
			b.logger.Fatal(err.Error())
		} else {
			b.logger.Error(err.Error())
		}
		return nil, nil // when not failing hard, we return no error
	}

	if len(*decision) >= 1 {
		return (*decision)[0], nil // TODO: decide if choosing the first decision is OK
	}

	return nil, nil

}
