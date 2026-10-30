package bouncer

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

// newTransport returns an [http.Transport] cloned from [http.DefaultTransport]
// with the given TLS configuration applied. Cloning matters: a zero-value
// http.Transport has no Proxy, no dial timeout, no TLS handshake timeout and
// no idle connection tuning, so a stalled connection to a LAPI that is still
// coming up consumes the caller's whole context budget.
func newTransport(tlsConfig *tls.Config) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	// http.DefaultTransport.Clone() carries ForceAttemptHTTP2: true. Go's
	// net/http disables automatic HTTP/2 when a Transport has a non-nil
	// TLSClientConfig and ForceAttemptHTTP2 is false -- which is what the
	// zero-value Transport this replaced did, so LAPI traffic ran over
	// HTTP/1.1. Leaving the cloned default as-is would silently switch HTTPS
	// LAPI connections to h2, subjecting the large chunked startup=true dump
	// to per-stream flow control it never had before -- the exact transfer
	// this timeout fix exists to protect. Force HTTP/1.1 to keep that
	// behaviour unchanged for everyone whose startup pull already succeeds.
	transport.ForceAttemptHTTP2 = false

	return transport
}

func NewAPIClient(urlstr string, apiKey string, userAgent string, caPath string, certPath string, keyPath string, skipVerify *bool, logger logrus.FieldLogger) (*apiclient.ApiClient, error) {
	var client *http.Client

	insecureSkipVerify := false

	if !strings.HasSuffix(urlstr, "/") {
		urlstr += "/"
	}

	apiURL, err := url.Parse(urlstr)
	if err != nil {
		return nil, fmt.Errorf("local API Url '%s': %w", urlstr, err)
	}

	if skipVerify != nil && *skipVerify {
		insecureSkipVerify = true
	}

	caCertPool, err := getCertPool(caPath, logger)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		var transport *apiclient.APIKeyTransport
		logger.Infof("Using API key auth")
		if apiURL.Scheme == "https" {
			transport = &apiclient.APIKeyTransport{
				APIKey: apiKey,
				Transport: newTransport(&tls.Config{
					RootCAs:            caCertPool,
					InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // opt-in via configuration
				}),
			}
		} else {
			transport = &apiclient.APIKeyTransport{
				APIKey: apiKey,
			}
		}
		client = transport.Client()
	}

	if certPath != "" && keyPath != "" {
		logger.Infof("Using cert auth with cert '%s' and key '%s'", certPath, keyPath)

		certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to load certificate '%s' and key '%s': %w", certPath, keyPath, err)
		}

		client = &http.Client{}
		client.Transport = newTransport(&tls.Config{
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{certificate},
			InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // opt-in via configuration
		})
	}

	return apiclient.NewDefaultClient(apiURL, "v1", userAgent, client)
}
