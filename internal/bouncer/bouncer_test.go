package bouncer

import (
	"net"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/jarcoal/httpmock"
	"github.com/pkg/errors"
	"go.uber.org/zap/zaptest"

	"github.com/google/go-cmp/cmp"
)

func new(t *testing.T) (*Bouncer, error) {

	key := "apiKey"
	host := "http://127.0.0.1:8080/"
	tickerInterval := "10s"
	logger := zaptest.NewLogger(t)

	bouncer, err := New(key, host, tickerInterval, logger)
	if err != nil {
		return nil, err
	}

	bouncer.EnableStreaming()

	// the code below mimicks the bouncer.streamingBouncer.Init() functionality
	bouncer.streamingBouncer.Stream = make(chan *models.DecisionsStreamResponse)

	apiURL, err := url.Parse(bouncer.streamingBouncer.APIUrl)
	if err != nil {
		return nil, errors.Wrapf(err, "local API Url '%s'", bouncer.streamingBouncer.APIUrl)
	}
	transport := &apiclient.APIKeyTransport{
		APIKey:    bouncer.streamingBouncer.APIKey,
		Transport: httpmock.DefaultTransport, // crucial for httpmock to work correctly
	}

	// logic in the NewDefaultClient is not really nice; it checks for an *http.Transport, which
	// the httpmock transport isn't, resulting in a panic. We've worked around this by specifying the
	// Transport in the APIKeyTransport and waiting a bit before the bouncer is ran. This results in
	// the goal of ensuring the bouncer gets mocked decisions.
	bouncer.streamingBouncer.APIClient, err = apiclient.NewDefaultClient(apiURL, "v1", bouncer.streamingBouncer.UserAgent, transport.Client())
	if err != nil {
		return nil, errors.Wrapf(err, "api client init")
	}

	bouncer.streamingBouncer.TickerIntervalDuration, err = time.ParseDuration(bouncer.streamingBouncer.TickerInterval)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse duration '%s'", bouncer.streamingBouncer.TickerInterval)
	}

	bouncer.streamingBouncer.Errors = make(chan error)

	// initialization of the bouncer finished; running is responsibility of the caller

	return bouncer, err
}

func decisions() *models.DecisionsStreamResponse {

	duration := "120s"
	source := "cscli"
	scenario := "manual ban ..."
	scopeIP := "Ip"
	scopeRange := "Range"
	typ := "ban"
	value1 := "127.0.0.1"
	value2 := "127.0.0.2"
	value3 := "10.0.0.1/24"

	return &models.DecisionsStreamResponse{
		Deleted: []*models.Decision{},
		New: []*models.Decision{
			{
				Duration: &duration,
				ID:       1,
				Origin:   &source,
				Scenario: &scenario,
				Scope:    &scopeIP,
				Type:     &typ,
				Value:    &value1,
			},
			{
				Duration: &duration,
				ID:       2,
				Origin:   &source,
				Scenario: &scenario,
				Scope:    &scopeIP,
				Type:     &typ,
				Value:    &value2,
			},
			{
				Duration: &duration,
				ID:       3,
				Origin:   &source,
				Scenario: &scenario,
				Scope:    &scopeRange,
				Type:     &typ,
				Value:    &value3,
			},
		},
	}
}

func TestStreamingBouncer(t *testing.T) {

	b, err := new(t)
	if err != nil {
		t.Fatal(err)
	}

	// activate httpmock so that responses can be mocked
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	// create a mock for the streaming bouncer; results in all mocked responses to be inserted
	decisions := decisions()
	urlRegexp := regexp.MustCompile(`http:\/\/127\.0\.0\.1:8080\/v1\/decisions\/stream\?startup=.*`)
	httpmock.RegisterRegexpResponder("GET", urlRegexp, httpmock.NewJsonResponderOrPanic(200, decisions))

	// run the bouncer; makes it make a call to the mocked CrowdSec API
	// this should be called after the httpmock is activated, because otherwise the bouncer
	// will try to call an actual CrowdSec instance
	b.Run()

	// allow the bouncer a bit of time to retrieve and store the mocked rules
	time.Sleep(1 * time.Second)

	type args struct {
		ip net.IP
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "127.0.0.1 not allowed",
			args: args{
				ip: net.ParseIP("127.0.0.1"),
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "127.0.0.2 not allowed",
			args: args{
				ip: net.ParseIP("127.0.0.2"),
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "127.0.0.3 allowed",
			args: args{
				ip: net.ParseIP("127.0.0.3"),
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "10.0.0.1/24 (10.0.0.1) not allowed",
			args: args{
				ip: net.ParseIP("10.0.0.1"),
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "10.0.1.0 allowed",
			args: args{
				ip: net.ParseIP("10.0.1.0"),
			},
			want:    true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		got, _, err := b.IsAllowed(tt.args.ip)
		if (err != nil) != tt.wantErr {
			t.Errorf("%q. b.IsAllowed() error = %v, wantErr %v", tt.name, err, tt.wantErr)
			continue
		}
		if !cmp.Equal(got, tt.want) {
			t.Errorf("%q. b.IsAllowed() = %v, want %v\ndiff=%s", tt.name, got, tt.want, cmp.Diff(got, tt.want))
		}
	}
}
