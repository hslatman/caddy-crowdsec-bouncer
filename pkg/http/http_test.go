package http

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/hslatman/caddy-crowdsec-bouncer/pkg/app"
	"github.com/hslatman/caddy-crowdsec-bouncer/pkg/bouncer"
)

func createCrowdSec(t *testing.T) (*app.CrowdSec, error) {

	// Mimicking Caddy Provision()
	apiKey := "key"
	apiURL := "url"
	tickerInterval := "10s"
	logger := zaptest.NewLogger(t)

	bouncer, err := bouncer.New(apiKey, apiURL, tickerInterval, logger)
	if err != nil {
		return nil, err
	}

	bouncer.EnableStreaming()

	if err := bouncer.Init(); err != nil {
		return nil, err
	}

	// Needs to be mocked, behind interface, made public
	// or provided in some other way, for example setting
	// up a full Caddy instance for testing purposes
	c := &app.CrowdSec{
		// bouncer: bouncer,
		// logger:  logger,
	}

	err = c.Validate()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func createHandler(t *testing.T) (*Handler, error) {

	// Mimicking the Caddy Provision() method
	c, err := createCrowdSec(t)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		crowdsec: c,
		logger:   zaptest.NewLogger(t),
	}

	err = h.Validate()
	if err != nil {
		return nil, err
	}

	return h, nil
}

func prepareRequest(ip, method, url string) (*http.Request, error) {

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}

	req.RemoteAddr = ip

	return req, nil
}

type nextHandler struct {
}

func (n *nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {

	w.Header().Set("Content-Type", "text/plain")

	w.Write([]byte("next, please ..."))
	w.WriteHeader(200)

	return nil
}

func TestHandler(t *testing.T) {

	// h, err := createHandler(t)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// next := &nextHandler{}

	req, err := prepareRequest("127.0.0.1", "GET", "http://127.0.0.1:9080/")
	if err != nil {
		t.Fatal(err)
	}

	// recorder := httptest.NewRecorder()

	// err = h.ServeHTTP(recorder, req, next)
	// if err == nil {
	// 	t.Error("expected an error while enforcing server validation")
	// }

	// TODO: find good approach for setting up Caddy with CrowdSec
	// running in the background. This requires some level of
	// coordination, because decision need to be added to CrowdSec
	// for a certain period of time, after which they'll be deleted
	// again. These changes will be "streamed" to the CrowdSec app.
	// We could also opt for mocking CrowdSec entirely. Another option
	// is to provide a mock client to Caddy, but that's probably
	// going to be had to plug into the current Caddy architecture or
	// may end up having to expose a certain configuration setting
	// for simulation/mocking usage.

	tester := caddytest.NewTester(t)

	tester.InitServer(`
	{   
		"apps": {
		  "crowdsec": {
			"api_key": "<api_key>",
			"api_url": "http://127.0.0.1:8080/",
			"ticker_interval": "10s",
			"enable_streaming": true,
			"enable_hard_fails": false
		  },
		  "http": {
			"http_port": 9080,
			"https_port": 9443,
			"servers": {
			  "server1": {
				"listen": [
				  "127.0.0.1:9080"
				],
				"routes": [
				  {
					"group": "temp-example-group",
					"match": [
					  {
						"path": [
						  "/*"
						]
					  }
					],
					"handle": [
					  {
						"handler": "crowdsec"
					  },
					  {
						"handler": "static_response",
						"status_code": "200",
						"body": "Hello World!"
					  },
					  {
						"handler": "headers",
						"response": {
						  "set": {
							"Server": ["caddy-cs-bouncer"]
						  }
						}
					  }
					]
				  }
				]
			  }
			}
		  }
		}
	  }
	`, "json")

	// fmt.Println(tester)
	// fmt.Println(fmt.Sprintf("%#+v", tester))

	time.Sleep(1000)

	// TODO: test fails if CrowdSec instance has
	// the IP 127.0.0.1 set to disallowed.
	r := tester.AssertResponseCode(req, 200)

	fmt.Println(r)
	fmt.Println(fmt.Sprintf("%#+v", r))

	// t.Fatal()
}
