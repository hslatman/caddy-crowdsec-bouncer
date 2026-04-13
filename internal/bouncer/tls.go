package bouncer

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

func getCertPool(caPath string, logger logrus.FieldLogger) (*x509.CertPool, error) {
	cp, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("unable to load system CA certificates: %w", err)
	}

	if cp == nil {
		cp = x509.NewCertPool()
	}

	if caPath == "" {
		return cp, nil
	}

	logger.Infof("Using CA cert '%s'", caPath)

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load CA certificate '%s': %w", caPath, err)
	}

	cp.AppendCertsFromPEM(caCert)

	return cp, nil
}
