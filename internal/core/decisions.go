package core

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (b *Core) startStreamingBouncer(ctx context.Context) {
	b.wg.Go(func() {
		b.logger.Debug("starting streaming bouncer", b.zapField())
		b.streamingBouncer.Run(ctx)
	})
}

func (b *Core) startProcessingDecisions(ctx context.Context) {
	b.wg.Go(func() {
		b.logger.Debug("starting decision processing", b.zapField())

		for {
			select {
			case <-ctx.Done():
				b.logger.Info("processing new and deleted decisions stopped", b.zapField())
				return
			case decisions, ok := <-b.streamingBouncer.Stream:
				if !ok {
					b.logger.Info("decision stream closed", b.zapField())
					return
				}
				if decisions == nil {
					continue
				}
				mustRecalculateDecisionCounts := false
				if pruned, err := b.store.pruneExpired(); err != nil {
					b.logger.Error("unable to prune expired decisions", b.zapField(), zap.Error(err))
				} else if pruned > 0 {
					mustRecalculateDecisionCounts = true
				}

				// Startup streams intentionally include old expired decisions as
				// tombstones. Deletion is idempotent, so process them normally.
				// TODO: process in separate goroutines/waitgroup?
				if numberOfDeletedDecisions := len(decisions.Deleted); numberOfDeletedDecisions > 0 {
					b.logger.Debug(fmt.Sprintf("processing %d deleted decisions", numberOfDeletedDecisions), b.zapField())
					for _, decision := range decisions.Deleted {
						if err := b.delete(decision); err != nil {
							b.logger.Error(fmt.Sprintf("unable to delete decision for %q: %s", decisionValue(decision), err), b.zapField())
						} else {
							if numberOfDeletedDecisions <= maxNumberOfDecisionsToLog {
								b.logger.Debug(fmt.Sprintf("deleted %q (scope: %s)", decisionValue(decision), decisionScope(decision)), b.zapField())
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
				if b.processNewDecisions(decisions.New) {
					mustRecalculateDecisionCounts = true
				}

				if mustRecalculateDecisionCounts && b.metricsProvider.UsageMetricsEnabled() {
					b.metricsProvider.RecalculateAndRecordDecisionCounts(b.store.activeDecisionSnapshot())
				}

				// send the (initial) metrics (once)
				b.metricsProvider.SendInitialMetricsOnce(ctx)
			}
		}
	})
}

func (b *Core) processNewDecisions(decisions []*models.Decision) bool {
	numberOfNewDecisions := len(decisions)
	if numberOfNewDecisions == 0 {
		return false
	}

	b.logger.Debug(fmt.Sprintf("processing %d new decisions", numberOfNewDecisions), b.zapField())
	receivedAt := b.store.now()
	for _, decision := range decisions {
		if err := b.add(decision, receivedAt); err != nil {
			b.logger.Error(fmt.Sprintf("unable to insert decision for %q: %s", decisionValue(decision), err), b.zapField())
		} else if numberOfNewDecisions <= maxNumberOfDecisionsToLog {
			b.logger.Debug(fmt.Sprintf("adding %q (scope: %s) for %q", decisionValue(decision), decisionScope(decision), decisionDuration(decision)), b.zapField())
		}
	}
	if numberOfNewDecisions > maxNumberOfDecisionsToLog {
		b.logger.Debug(fmt.Sprintf("skipped logging for %d new decisions", numberOfNewDecisions), b.zapField())
	}
	b.logger.Debug(fmt.Sprintf("finished processing %d new decisions", numberOfNewDecisions), b.zapField())

	return true
}

// add adds a Decision to the storage
func (b *Core) add(decision *models.Decision, receivedAt time.Time) error {
	// TODO: provide additional ways for storing the decisions
	// (i.e. radix tree is not always the most efficient one, but it's great for matching IPs to ranges)
	// Knowing that a key is a CIDR does allow to check an IP with the .Contains() function, but still
	// requires looping through the ranges

	// TODO: store additional data about the decision (i.e. time added to store, etc)
	// TODO: wrap the *models.Decision in an internal model (after validation)?

	return b.store.addAt(decision, receivedAt)
}

// delete removes a Decision from the storage
func (b *Core) delete(decision *models.Decision) error {
	return b.store.delete(decision)
}

func (b *Core) retrieveDecision(ctx context.Context, ip netip.Addr, forceLive bool, method string) (*models.Decision, error) {
	if b.useStreamingBouncer && !forceLive {
		return b.store.get(ip)
	}

	decisions, err := b.liveBouncer.Get(ctx, ip.String(), method)
	if err != nil {
		fields := []zapcore.Field{
			b.zapField(),
			zap.String("address", b.apiURL),
			zap.Error(err),
		}

		if b.shouldFailHard {
			b.logger.Fatal(err.Error(), fields...)
		} else {
			b.logger.Error(err.Error(), fields...)
		}

		return nil, nil // when not failing hard, we return no error
	}

	if decisions == nil {
		return nil, nil
	}

	return selectDecision(ip, []*models.Decision(*decisions))
}

func decisionValue(decision *models.Decision) string {
	if decision == nil || decision.Value == nil {
		return ""
	}

	return *decision.Value
}

func decisionScope(decision *models.Decision) string {
	if decision == nil || decision.Scope == nil {
		return ""
	}

	return *decision.Scope
}

func decisionDuration(decision *models.Decision) string {
	if decision == nil || decision.Duration == nil {
		return ""
	}

	return *decision.Duration
}
