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
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"go.uber.org/zap"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/version"
)

const (
	userAgentName             = "caddy-cs-bouncer"
	maxNumberOfDecisionsToLog = 10
)

var (
	userAgent        string
	userAgentVersion string
)

func init() {
	userAgentVersion = version.Current()
	userAgent = userAgentName + "/" + userAgentVersion
}

// Bouncer is a wrapper for a CrowdSec bouncer. It supports both the
// streaming and live bouncer implementations. The streaming bouncer is
// backed by an immutable radix tree storing known bad IPs and IP ranges.
// The live bouncer will reach out to the CrowdSec LAPI on every check.
type Bouncer struct {
	streamingBouncer    *csbouncer.StreamBouncer
	liveBouncer         *csbouncer.LiveBouncer
	metricsProvider     *csbouncer.MetricsProvider
	appsec              *appsec
	store               *store
	logger              *zap.Logger
	useStreamingBouncer bool
	shouldFailHard      bool
	userAgent           string
	instantiatedAt      time.Time
	instanceID          string

	ctx       context.Context
	started   bool
	stopped   bool
	startedAt time.Time
	startMu   sync.Mutex
	cancel    context.CancelFunc
	wg        *sync.WaitGroup
}

// New creates a new (streaming) Bouncer with a storage based on immutable radix tree
func New(apiKey, apiURL, appSecURL string, appSecMaxBodySize int, tickerInterval string, logger *zap.Logger) (*Bouncer, error) {
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
		appsec:         newAppSec(appSecURL, apiKey, appSecMaxBodySize, logger.Named("appsec")),
		store:          newStore(),
		logger:         logger,
		userAgent:      userAgent,
		instantiatedAt: instantiatedAt,
		instanceID:     instanceID,
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

func (b *Bouncer) NumberOfActiveDecisions() int {
	return b.store.store.Len()
}

func (b *Bouncer) UserAgent() string {
	return b.userAgent
}

func (b *Bouncer) StartedAt() time.Time {
	return b.instantiatedAt
}

func (b *Bouncer) InstanceID() string {
	return b.instanceID
}

// Init initializes the Bouncer
func (b *Bouncer) Init() (err error) {
	// override CrowdSec's default logrus logging
	b.overrideLogrusLogger()

	// TODO: make metrics gathering/integration optional? I.e. if the metrics
	// interval is configured to be 0 or smaller, don't start the metrics
	// provider? Separate setting for gathering metrics vs. pushing to LAPI?
	metricsInterval := 1 * time.Minute

	// conditionally initialize the CrowdSec live bouncer
	if !b.useStreamingBouncer {
		b.logger.Info("initializing live bouncer", b.zapField())
		if err = b.liveBouncer.Init(); err != nil {
			return err
		}
	}

	// conditionally initialize the CrowdSec streaming bouncer. The
	// live bouncer is also initialized for ad hoc live lookups.
	if b.useStreamingBouncer {
		b.logger.Info("initializing streaming bouncer", b.zapField())
		if err = b.streamingBouncer.Init(); err != nil {
			return err
		}

		b.logger.Info("initializing live bouncer for ad hoc live lookups", b.zapField())
		if err = b.liveBouncer.Init(); err != nil {
			return err
		}
	}

	if b.metricsProvider, err = newMetricsProvider(b.liveBouncer.APIClient, b.updateMetrics, metricsInterval); err != nil {
		return err
	}

	b.logAppSecStatus()

	return nil
}

// Run starts the Bouncer processes
func (b *Bouncer) Run(ctx context.Context) {
	b.startMu.Lock()
	defer b.startMu.Unlock()
	if b.started {
		return
	}

	b.wg = &sync.WaitGroup{}
	b.ctx, b.cancel = context.WithCancel(ctx)

	b.started = true
	b.startedAt = time.Now()
	b.logger.Info("started", b.zapField())

	// when using the live bouncer only the metrics provider needs
	// to be initialized. Return early without starting other processes.
	if !b.useStreamingBouncer {
		b.startMetricsProvider(b.ctx)

		return
	}

	// TODO: close the stream nicely when the bouncer needs to quit. This is not done
	// in the csbouncer package itself when canceling.
	// TODO: wait with processing until we know we're successfully connected to
	// the CrowdSec API? The bouncer/client doesn't seem to give us that information
	// directly, but we could use the heartbeat service before starting to run?
	// That can also be useful for testing the LiveBouncer at startup.
	// NOTE: heartbeat service can't be used by LiveBouncer; it will result in 401s
	// when trying to use that, it seems. It might be just for CrowdSec "machines".
	// The Bouncer now has a method Ping that can be used in lieu of the heartbeat.

	b.startStreamingBouncer(b.ctx)
	b.startProcessingDecisions(b.ctx)
	b.startMetricsProvider(b.ctx)
}

// Shutdown stops the Bouncer
func (b *Bouncer) Shutdown() error {
	b.startMu.Lock()
	defer b.startMu.Unlock()
	if !b.started || b.stopped {
		return nil
	}

	b.logger.Info("stopping ...", b.zapField())

	b.cancel()
	b.wg.Wait()

	// TODO: clean shutdown of the streaming bouncer channel reading
	//b.store = nil // TODO(hs): setting this to nil without reinstantiating it, leads to errors; do this properly.

	b.stopped = true
	b.logger.Info("finished", b.zapField())
	b.logger.Sync() // nolint

	return nil
}

// IsAllowed checks if an IP is allowed or not
func (b *Bouncer) IsAllowed(ip netip.Addr, forceLive bool) (bool, *models.Decision, error) {
	// TODO: perform lookup in explicit allowlist as a kind of quick lookup in front of the CrowdSec lookup list?
	isAllowed := false
	if !ip.IsValid() {
		return isAllowed, nil, errors.New("could not obtain netip.Addr from request") // fail closed
	}

	decision, err := b.retrieveDecision(ip, forceLive)
	if err != nil {
		return isAllowed, nil, err // fail closed
	}

	if decision != nil {
		return isAllowed, decision, nil
	}

	// at this point we've determined the IP is allowed
	isAllowed = true

	return isAllowed, nil, nil
}

func (b *Bouncer) CheckRequest(ctx context.Context, r *http.Request) error {
	return b.appsec.checkRequest(ctx, r)
}

func generateInstanceID(t time.Time) (string, error) {
	r := rand.New(rand.NewSource(t.Unix()))
	b := [4]byte{}
	if _, err := r.Read(b[:]); err != nil {
		return "", err
	}

	return hex.EncodeToString(b[:]), nil
}
