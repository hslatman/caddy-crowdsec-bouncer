package bouncer

import (
	"fmt"
	"net"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"go.uber.org/zap/zaptest"
)

func new(t *testing.T) (*Bouncer, error) {

	apiKey := "apiKey"
	apiURL := "apiURL"
	tickerInterval := "10s"
	logger := zaptest.NewLogger(t)

	bouncer, err := New(apiKey, apiURL, tickerInterval, logger)
	if err != nil {
		return nil, err
	}

	bouncer.EnableStreaming()

	return bouncer, err
}

type testCase struct {
}

func decisionForIP(ip string) *models.Decision {
	return decision(ip)
}

func decisionForCIDR(cidr string) *models.Decision {
	return decision(cidr)
}

func decision(ipOrCIDR string) *models.Decision {

	scope := "Ip"
	value := ipOrCIDR
	duration := "30m"
	typ := "ban"
	origin := "test"
	scenario := "test"

	decision := &models.Decision{
		Scope:    &scope,
		Value:    &value,
		Duration: &duration,
		Type:     &typ,
		Origin:   &origin,
		Scenario: &scenario,
	}

	return decision
}

func TestBouncer(t *testing.T) {

	b, err := new(t)
	if err != nil {
		t.Fatal(err)
	}

	ipString := "127.0.0.1"
	ip := net.ParseIP(ipString)
	isAllowed, _, err := b.IsAllowed(ip)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(isAllowed)

	if isAllowed != true {
		t.Error(fmt.Sprintf("expected true; got: %t", isAllowed))
	}

	d := decision(ipString)
	b.add(d)

	isAllowed, _, err = b.IsAllowed(ip)
	if err != nil {
		t.Error(err)
	}

	if isAllowed != false {
		t.Error(fmt.Sprintf("expected false; got: %t", isAllowed))
	}

}
