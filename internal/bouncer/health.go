package bouncer

import (
	"context"
	"fmt"
)

// Healthy reports whether the [Bouncer]'s current state is considered
// healthy.
func (b *Bouncer) Healthy(ctx context.Context) (bool, error) {
	return b.Ping(ctx) // TODO: more checks? Make this _not_ depend on (new) external calls?
}

// Ping "pings" the CrowdSec LAPI to verify a successful connection can be
// made. It looks up the broadcast IP for the localhost IP address range, which
// realistically should never be blocked. A successful response thus indicates
// that a connection could be made.
func (b *Bouncer) Ping(ctx context.Context) (bool, error) {
	if _, err := b.liveBouncer.Get("127.0.0.255"); err != nil {
		return false, fmt.Errorf("failed reaching CrowdSec LAPI: %w", err)
	}

	return true, nil
}
