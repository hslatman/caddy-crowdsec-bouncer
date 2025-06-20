package adminapi

import "time"

type Streaming struct {
	Enabled  bool
	Interval string
}

type Live struct {
	Enabled bool
	Mode    string
}

type AppSec struct {
	Enabled bool
}

type InfoResponse struct {
	Streaming               Streaming
	Live                    Live
	AppSec                  AppSec
	ShouldFailHard          bool
	AuthType                string
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
