package bouncer

type AppSecError struct {
	Err        error
	Action     string
	Duration   string
	StatusCode int
}

func (a AppSecError) Error() string {
	return a.Err.Error()
}
