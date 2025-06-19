package bouncer

import "context"

func (b *Bouncer) Healthy(ctx context.Context) (bool, error) {
	ok, _, err := b.liveBouncer.APIClient.HeartBeat.Ping(ctx) // TODO: more checks?

	return ok, err
}

func (b *Bouncer) Ping(ctx context.Context) (bool, error) {
	ok, _, err := b.liveBouncer.APIClient.HeartBeat.Ping(ctx)

	return ok, err
}
