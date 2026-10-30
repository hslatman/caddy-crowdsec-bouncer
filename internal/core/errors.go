package core

import "net/http"

type AppSecError struct {
	Err        error
	Action     string
	Duration   string
	StatusCode int

	// Challenge is set when the AppSec component asks for the client to be
	// served a bot detection challenge instead of being blocked.
	Challenge *Challenge
}

func (a AppSecError) Error() string {
	return a.Err.Error()
}

// Challenge is the response the AppSec component wants relayed to the client
// for a "challenge" remediation: the challenge page, one of its assets, or the
// result of a challenge submission.
type Challenge struct {
	StatusCode int
	Headers    http.Header
	Cookies    []string
	Body       string
}
