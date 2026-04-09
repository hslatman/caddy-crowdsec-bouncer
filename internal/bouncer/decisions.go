package bouncer

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (b *Bouncer) startStreamingBouncer(ctx context.Context) {
	b.wg.Go(func() {
		b.logger.Debug("starting streaming bouncer", b.zapField())
		b.streamingBouncer.Run(ctx)
	})
}

func (b *Bouncer) startProcessingDecisions(ctx context.Context) {
	b.wg.Go(func() {
		b.logger.Debug("starting decision processing", b.zapField())

		for {
			select {
			case <-ctx.Done():
				b.logger.Info("processing new and deleted decisions stopped", b.zapField())
				return
			case decisions := <-b.streamingBouncer.Stream:
				if decisions == nil {
					continue
				}
				// TODO: deletions seem to include all old decisions that had already expired; CrowdSec bug or intended behavior?
				// TODO: process in separate goroutines/waitgroup?
				mustRecalculateDecisionCounts := false
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
					mustRecalculateDecisionCounts = true
				}

				// TODO: process in separate goroutines/waitgroup?
				// TODO: emit a Caddy event at the end of processing (new) decisions?
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
					mustRecalculateDecisionCounts = true
				}

				if mustRecalculateDecisionCounts {
					b.recalculateAndRecordDecisionCounts()
				}

				// send the (initial) metrics (once)
				b.metricsProvider.sendInitialMetricsOnce(ctx)
			}
		}
	})
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

func (b *Bouncer) retrieveDecision(ip netip.Addr, forceLive bool) (*models.Decision, error) {
	if b.useStreamingBouncer && !forceLive {
		return b.store.get(ip)
	}

	totalBouncerCallsCounter.Inc() // increment; not built into liveBouncer
	decisions, err := b.liveBouncer.Get(ip.String())
	if err != nil {
		totalBouncerErrorsCounter.Inc() // increment; not built into liveBouncer
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

	if len(*decisions) >= 1 {
		return (*decisions)[0], nil // TODO: decide if choosing the first decision is OK
	}

	return nil, nil
}

type ipType string

const (
	ipv4 ipType = "ipv4"
	ipv6 ipType = "ipv6"
)

func (b *Bouncer) recalculateAndRecordDecisionCounts() {
	// initialize map, so that these origins are always
	// known and recorded
	m := map[string]map[ipType]int{
		"CAPI":             {ipv4: 0, ipv6: 0},
		"crowdsec":         {ipv4: 0, ipv6: 0},
		"cscli":            {ipv4: 0, ipv6: 0},
		"cscli-import":     {ipv4: 0, ipv6: 0},
		"console":          {ipv4: 0, ipv6: 0},
		"appsec":           {ipv4: 0, ipv6: 0},
		"remediation_sync": {ipv4: 0, ipv6: 0},
	}

	for prefix, v := range b.store.store.All() {
		origin := *v.Origin
		isIPv6 := prefix.Bits() > 32
		n, ok := m[origin]
		if !ok {
			n = map[ipType]int{ipv4: 0, ipv6: 0}
			m[origin] = n
		}

		if isIPv6 {
			n[ipv6] += 1
		} else {
			n[ipv4] += 1
		}
	}

	// update the count of active decisions per origin and IP type
	for origin, tuple := range m {
		for ipType, count := range tuple {
			activeDecisionsGauge.With(map[string]string{"origin": origin, "ip_type": string(ipType)}).Set(float64(count))
		}
	}
}
