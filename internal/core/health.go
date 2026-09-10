package core

import (
	"context"
	"fmt"
	"time"
)

// StreamStale reports whether the streaming bouncer has gone too long without
// a successful decision pull -- the decoupled freeze signal. It fills the gap
// that a frozen stream (persistent error, rejected key) was invisible: Run never
// returns, nothing is logged at a level anyone watches, and no metric moves.
func (b *Core) StreamStale() bool {
	last := b.streamingBouncer.LastSuccessfulPull()
	if last.IsZero() {
		// Never connected successfully: only count as frozen once the startup
		// window has passed, measured from instantiation.
		return time.Since(b.instantiatedAt) > b.streamStaleThreshold
	}
	return time.Since(last) > b.streamStaleThreshold
}

// streamIsOurs decides whether a stale stream is the bouncer's own problem (a
// restart helps) or the LAPI's (a restart would not help, and would only
// amplify an outage across every tenant sharing that LAPI). It probes the LAPI
// once and classifies the answer:
//
//   - success or 4xx: the LAPI is up. Our key or request is rejected, or our
//     stream alone is stuck -> ours; a restart re-registers and reconnects.
//   - 5xx or no answer (transport failure): the LAPI is failing or unreachable
//     -> not ours; the LAPI-down and agent alerts cover that case.
func (b *Core) streamIsOurs(ctx context.Context) bool {
	status, err := b.liveBouncer.Probe(ctx)
	if err == nil {
		return true
	}
	return status >= 400 && status < 500
}

// Healthy reports whether the [Core]'s current state is considered
// healthy.
//
// When streaming, the freshness of the decision pull is the signal, decoupled
// from a live Ping: a brief LAPI blip must not read unhealthy (transient errors
// self-heal on the next tick), and no LAPI call is made at all while the stream
// is fresh. A stale stream is classified before it is reported -- only a stale
// stream that is ours to fix reads unhealthy, which is what a liveness probe
// should restart on. Without streaming it falls back to the live Ping.
func (b *Core) Healthy(ctx context.Context) (bool, error) {
	if !b.useStreamingBouncer {
		return b.Ping(ctx)
	}
	if !b.StreamStale() {
		return true, nil
	}
	if !b.streamIsOurs(ctx) {
		// The LAPI is failing or unreachable: not ours to fix. Report healthy so
		// a liveness probe does not restart caddy into a still-broken LAPI.
		return true, nil
	}
	return false, fmt.Errorf("crowdsec decision stream is stale (no successful pull within %s) although the LAPI answers -- the stream is ours to fix", b.streamStaleThreshold)
}

// Ping "pings" the CrowdSec LAPI to verify a successful connection can be
// made. It looks up the broadcast IP for the localhost IP address range, which
// realistically should never be blocked. A successful response thus indicates
// that a connection could be made.
func (b *Core) Ping(ctx context.Context) (bool, error) {
	if _, err := b.liveBouncer.Get(ctx, "127.0.0.255", "ping"); err != nil {
		return false, fmt.Errorf("failed reaching CrowdSec LAPI: %w", err) // TODO: distinguish specific types of errors
	}

	return true, nil
}
