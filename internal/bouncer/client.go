package bouncer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
)

func getAPIClient(urlstr string, userAgent string, apiKey string, caPath string, certPath string, keyPath string, skipVerify *bool, logger logrus.FieldLogger) (*apiclient.ApiClient, error) {
	var client *http.Client

	if apiKey == "" && certPath == "" && keyPath == "" {
		return nil, errors.New("no API key nor certificate provided")
	}

	if apiKey != "" && (certPath != "" || keyPath != "") {
		return nil, fmt.Errorf("cannot use both API key and certificate auth")
	}

	insecureSkipVerify := false

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
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs:            caCertPool,
						InsecureSkipVerify: insecureSkipVerify,
					},
				},
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
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				Certificates:       []tls.Certificate{certificate},
				InsecureSkipVerify: insecureSkipVerify,
			},
		}
	}

	return apiclient.NewDefaultClient(apiURL, "v1", userAgent, client)
}
