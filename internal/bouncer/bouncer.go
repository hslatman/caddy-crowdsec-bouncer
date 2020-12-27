// Copyright 2020 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bouncer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	iradix "github.com/hashicorp/go-immutable-radix"
	"go.uber.org/zap"
)

func New(apiKey, apiURL, tickerInterval string, logger *zap.Logger) (*Bouncer, error) {
	return &Bouncer{
		streamingBouncer: &csbouncer.StreamBouncer{
			APIKey:         apiKey,
			APIUrl:         apiURL,
			TickerInterval: tickerInterval,
			UserAgent:      "caddy-cs-bouncer",
		},
		store:  iradix.New(),
		logger: logger,
	}, nil
}

type Bouncer struct {
	streamingBouncer *csbouncer.StreamBouncer
	store            *iradix.Tree
	logger           *zap.Logger
}

func (b *Bouncer) Init() error {
	return b.streamingBouncer.Init()
}

func (b *Bouncer) Run() {

	// TODO: handle errors? Return it to caller?

	go func() error {
		b.logger.Debug("Processing new and deleted decisions . . .")
		for {
			select {
			// case <-t.Dying():
			// 	c.logger.Info("terminating bouncer process")
			// 	return nil
			case decisions := <-b.streamingBouncer.Stream:
				b.logger.Debug("got decision ...")
				fmt.Println(decisions)
				//c.logger.Info("deleting '%d' decisions", len(decisions.Deleted))
				for _, decision := range decisions.Deleted {
					if err := b.Delete(decision); err != nil {
						//c.logger.Error("unable to delete decision for '%s': %s", *decision.Value, err)
					} else {
						//c.logger.Debug("deleted '%s'", *decision.Value)
					}

				}
				//c.logger.Info("adding '%d' decisions", len(decisions.New))
				for _, decision := range decisions.New {
					if err := b.Add(decision); err != nil {
						//c.logger.Error("unable to insert decision for '%s': %s", *decision.Value, err)
					} else {
						//c.logger.Debug("Adding '%s' for '%s'", *decision.Value, *decision.Duration)
					}
				}
			}
		}
	}()

	// TODO: handle connection errors in here? Soft or hard fail? Reconnects?
	go b.streamingBouncer.Run()
}

func (b *Bouncer) Add(decision *models.Decision) error {

	//fmt.Println(decision)
	//fmt.Println(fmt.Sprintf("%+v", decision))
	//fmt.Println(database.Int2ip(decision.StartIP))
	//fmt.Println(decision.StartIP) // first ip in ip range
	//fmt.Println(fmt.Sprintf("%#+v", *decision.Type)) // ban, captcha, throttle
	//fmt.Println(fmt.Sprintf("%#+v", *decision.Value)) // the value of decision (i.e. IP, range, username)
	//fmt.Println(decision.EndIP) // final IP in ip range
	//fmt.Println(decision.ID) // internal ID
	//fmt.Println(fmt.Sprintf("%#+v", *decision.Scenario)); what CS scenario this decision is related to?
	//fmt.Println(fmt.Sprintf("%#+v", *decision.Origin)); cscli, for example; others?
	//fmt.Println(fmt.Sprintf("%#+v", *decision.Simulated)); whether nor not simulated attack?
	//fmt.Println(fmt.Sprintf("%#+v", *decision.Scope)); ip, range, username;

	ipOrCIDR, err := findIPOrCIDR(decision)
	if err != nil {
		return err
	}

	b.logger.Info(fmt.Sprintf("adding %s ...", ipOrCIDR))

	//newRoot, oldValue, added := b.store.Insert([]byte(ipOrCIDR), decision)
	// TODO: store lookup as binary / number instead?
	// TODO: store additional data about the decision (i.e. time added to store, etc)
	newRoot, _, _ := b.store.Insert([]byte(ipOrCIDR), decision)

	b.store = newRoot

	fmt.Println(b.store.Len())

	// TODO: other cases to handle? The thing added by CS is then not valid, though ...

	return nil
}

func (b *Bouncer) Delete(decision *models.Decision) error {

	ipOrCIDR, err := findIPOrCIDR(decision)
	if err != nil {
		return err
	}

	b.logger.Info(fmt.Sprintf("deleting %s ...", ipOrCIDR))

	newRoot, _, _ := b.store.Delete([]byte(ipOrCIDR))

	b.store = newRoot

	fmt.Println(b.store.Len())

	return nil
}

func (b *Bouncer) IsAllowed(ip string) (bool, *models.Decision, error) {

	// TODO: also support IP range search instead of full match
	value, found := b.store.Get([]byte(ip))

	if found {
		v, ok := value.(*models.Decision)
		if !ok {
			return false, nil, fmt.Errorf("wrong type in storage: %T", value)
		}

		return false, v, nil
	}

	return true, nil, nil
}

func (b *Bouncer) ShutDown() error {
	return nil
}

func serializeDecision(decision *models.Decision) (string, error) {
	serbyte, err := json.Marshal(decision)
	if err != nil {
		return "", fmt.Errorf("serialize error : %s", err)
	}
	return string(serbyte), nil
}

func findIPOrCIDR(decision *models.Decision) (string, error) {

	var ipOrCIDR string
	scope := *decision.Scope

	switch scope {
	case "Ip":
		ip := net.ParseIP(*decision.Value)
		if ip != nil {
			ipOrCIDR = ip.String()
		}
	case "Range":
		_, ipNet, err := net.ParseCIDR(*decision.Value)
		if err == nil && ipNet != nil {
			ipOrCIDR = ipNet.String()
		}
	default:
		fmt.Println(fmt.Sprintf("got unhandled scope: %s", scope))
	}

	if ipOrCIDR == "" {
		return "", errors.New("no IP or CIDR found")
	}

	return ipOrCIDR, nil
}
