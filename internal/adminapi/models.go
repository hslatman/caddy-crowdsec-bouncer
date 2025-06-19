package adminapi

import "time"

type InfoResponse struct {
	BouncerEnabled          bool
	AppSecEnabled           bool
	StreamingEnabled        bool
	ShouldFailHard          bool
	UserAgent               string
	InstanceID              string
	Uptime                  time.Duration
	NumberOfActiveDecisions int

	// TODO: more properties? I.e. modules built into binary, modules
	// enabled, some of the metrics?, whether or not last call to LAPI was an
	// error?
	// TODO: restructure?
}

type HealthResponse struct {
	Ok bool
}

type PingResponse struct {
	Ok bool
}

type CheckRequest struct {
	IP        string
	ForceLive bool
}

type CheckResponse struct {
	Blocked bool
	Reason  string
}
