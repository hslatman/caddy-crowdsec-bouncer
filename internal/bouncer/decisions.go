package bouncer

import (
	"context"
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (b *Bouncer) startStreamingBouncer(ctx context.Context) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		b.logger.Debug("starting streaming bouncer", b.zapField())
		b.streamingBouncer.Run(ctx)
	}()
}

func (b *Bouncer) startProcessingDecisions(ctx context.Context) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		b.logger.Debug("starting decision processing", b.zapField())

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
