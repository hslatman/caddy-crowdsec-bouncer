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
	// DecisionStorePopulated reports whether the streaming decision store has
	// been filled by at least one successful LAPI pull. False while streaming
	// startup is still failing -- during which every request is allowed --
	// and always false in live mode.
	DecisionStorePopulated bool

	// TODO: more properties? I.e. modules built into binary, modules
	// enabled, some of the metrics?
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
