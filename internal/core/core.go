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

package core

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
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"go.uber.org/zap"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/bouncer"
	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
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

// Core is a wrapper for a CrowdSec bouncer. It supports both the
// streaming and live bouncer implementations. The streaming bouncer is
// backed by an immutable radix tree storing known bad IPs and IP ranges.
// The live bouncer will reach out to the CrowdSec LAPI on every check.
type Core struct {
	streamingBouncer    *bouncer.StreamBouncer
	liveBouncer         *bouncer.LiveBouncer
	metricsProvider     *metrics.Provider
	appsec              *appsec
	store               *store
	logger              *zap.Logger
	useStreamingBouncer bool
	shouldFailHard      bool
	userAgent           string
	instantiatedAt      time.Time
	instanceID          string
	apiURL              string

	ctx       context.Context
	started   bool
	stopped   bool
	startedAt time.Time
	startMu   sync.Mutex
	cancel    context.CancelFunc
	wg        *sync.WaitGroup
}

// New creates a new Bouncer with a storage based on immutable radix tree.
func New(apiKey, apiURL string, streamingEnabled bool, appSecURL string, appSecMaxBodySize int, appSecTimeout time.Duration, appSecFailOpen bool, tickerInterval time.Duration, shouldFailHard bool, logger *zap.Logger, caddyMetricsRegistry *prometheus.Registry, metricsInterval time.Duration) (*Core, error) {
	insecureSkipVerify := false
	instantiatedAt := time.Now()
	instanceID, err := generateInstanceID(instantiatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed generating instance ID: %w", err)
	}

	apiClient, err := bouncer.NewAPIClient(apiURL, apiKey, userAgent, "", "", "", &insecureSkipVerify, log.StandardLogger())
	if err != nil {
		return nil, err
	}

	metricsRegistry := prometheus.NewRegistry()
	metricsProvider, err := metrics.NewProvider(apiClient, metricsRegistry, caddyMetricsRegistry, metricsInterval, logger, userAgentName, userAgentVersion, instanceID)
	if err != nil {
		return nil, err
	}

	retryInitialConnect := !shouldFailHard
	streamingBouncer, err := bouncer.NewStreamBouncer(apiClient, metricsProvider, tickerInterval, retryInitialConnect)
	if err != nil {
		return nil, err
	}

	liveBouncer, err := bouncer.NewLiveBouncer(apiClient, metricsProvider)
	if err != nil {
		return nil, err
	}

	appsec := newAppSec(appSecURL, apiKey, appSecMaxBodySize, appSecTimeout, appSecFailOpen, logger.Named("appsec"), metricsProvider)
	store := newStore()

	return &Core{
		apiURL:              apiURL,
		streamingBouncer:    streamingBouncer,
		useStreamingBouncer: streamingEnabled,
		liveBouncer:         liveBouncer,
		appsec:              appsec,
		store:               store,
		metricsProvider:     metricsProvider,
		logger:              logger, // TODO add fields here?
		shouldFailHard:      shouldFailHard,
		userAgent:           userAgent,
		instantiatedAt:      instantiatedAt,
		instanceID:          instanceID,
	}, nil
}

func (b *Core) NumberOfActiveDecisions() int {
	return b.store.store.Len()
}

func (b *Core) UserAgent() string {
	return b.userAgent
}

func (b *Core) StartedAt() time.Time {
	return b.instantiatedAt
}

func (b *Core) InstanceID() string {
	return b.instanceID
}

// Init initializes the Bouncer
func (b *Core) Init() (err error) {
	// override CrowdSec's default logrus logging
	b.overrideLogrusLogger()

	// conditionally initialize the CrowdSec streaming bouncer. The
	// live bouncer is also initialized for ad hoc live lookups.
	if b.useStreamingBouncer {
		b.logger.Info("initializing streaming bouncer", b.zapField())
		b.logger.Info("initializing live bouncer for ad hoc live lookups", b.zapField())
	} else {
		b.logger.Info("initializing live bouncer", b.zapField())
	}

	b.logAppSecStatus()

	return nil
}

// Run starts the Bouncer processes
func (b *Core) Run(ctx context.Context) {
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
func (b *Core) Shutdown() error {
	b.startMu.Lock()
	defer b.startMu.Unlock()
	if !b.started || b.stopped {
		return nil
	}

	b.logger.Info("stopping ...", b.zapField())

	b.cancel()
	b.wg.Wait()

	// TODO: clean shutdown of the streaming bouncer channel writing/reading?

	b.logger.Warn("setting store nil") // TODO: remove
	b.store = nil

	b.stopped = true
	b.logger.Info("finished shutdown", b.zapField())
	_ = b.logger.Sync()

	return nil
}

// IsAllowed checks if an IP is allowed or not
func (b *Core) IsAllowed(ctx context.Context, ip netip.Addr, forceLive bool, method string) (bool, *models.Decision, error) {
	isAllowed, decision, err := b.isAllowed(ctx, ip, forceLive, method)
	return isAllowed, decision, err
}

func (b *Core) isAllowed(ctx context.Context, ip netip.Addr, forceLive bool, method string) (bool, *models.Decision, error) {
	// TODO: perform lookup in explicit allowlist as a kind of quick lookup in front of the CrowdSec lookup list?
	isAllowed := false

	if !ip.IsValid() {
		return isAllowed, nil, errors.New("could not obtain netip.Addr from request") // fail closed
	}

	decision, err := b.retrieveDecision(ctx, ip, forceLive, method)
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

func (b *Core) CheckRequest(ctx context.Context, r *http.Request) error {
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
