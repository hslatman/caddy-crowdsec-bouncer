// Copyright 2021 Herman Slatman
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

package crowdsec

import (
	"fmt"
	"net"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/hslatman/ipstore/pkg/ipstore"
)

type crowdSecStore struct {
	store *ipstore.Store
}

func newStore() *crowdSecStore {
	return &crowdSecStore{
		store: ipstore.New(),
	}
}

func (s *crowdSecStore) Add(decision *models.Decision) error {

	scope := *decision.Scope
	value := *decision.Value

	switch scope {
	case "Ip":
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("could not parse an IP from %s", value)
		}
		return s.store.Add(ip, decision)
	case "Range":
		_, net, err := net.ParseCIDR(value)
		if err != nil {
			return err
		}
		return s.store.AddCIDR(*net, decision)
	default:
		return fmt.Errorf("got unhandled scope: %s", scope)
	}
}

func (s *crowdSecStore) Delete(decision *models.Decision) error {
	scope := *decision.Scope
	value := *decision.Value

	switch scope {
	case "Ip":
		ip := net.ParseIP(value)
		if ip == nil {
			return fmt.Errorf("could not parse an IP from %s", value)
		}
		_, err := s.store.Remove(ip)
		return err
	case "Range":
		_, net, err := net.ParseCIDR(value)
		if err != nil {
			return err
		}
		_, err = s.store.RemoveCIDR(*net)
		return err
	default:
		return fmt.Errorf("got unhandled scope: %s", scope)
	}
}

func (s *crowdSecStore) Get(key net.IP) (*models.Decision, error) {

	r, err := s.store.Get(key)
	if err != nil {
		return nil, err
	}

	if len(r) == 0 {
		return nil, nil
	}

	// currently we return the first match, but the IP can exist in multiple
	// networks (CIDR ranges) and there may thus be multiple Decisions to act
	// upon. In general, though, the existince of at least a single Decision
	// means that the IP should not be allowed, so it's relatively safe to use
	// the first, but there may be 'softer' Decisions that should actually take
	// precedence.
	first, ok := r[0].(*models.Decision)
	if !ok {
		return nil, fmt.Errorf("invalid type retrieved from store")
	}

	return first, err
}
