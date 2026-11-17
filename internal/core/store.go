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

package core

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/hslatman/ipstore"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
)

type store struct {
	mu      sync.RWMutex
	index   *ipstore.Store[*decisionBucket]
	buckets map[netip.Prefix]*decisionBucket
	byID    map[int64]decisionLocation
	count   int
}

// decisionKey is the exact key deduplicated by LAPI's default stream. Origin
// and decision ID identify its effective member, not an independent group.
type decisionKey struct {
	scope string
	typ   string
	value string
}

type decisionBucket struct {
	decisions map[decisionKey]*models.Decision
	order     []decisionKey
}

type decisionLocation struct {
	prefix netip.Prefix
	key    decisionKey
}

func newStore() *store {
	return &store{
		index:   ipstore.New[*decisionBucket](),
		buckets: make(map[netip.Prefix]*decisionBucket),
		byID:    make(map[int64]decisionLocation),
	}
}

func (s *store) add(decision *models.Decision) error {
	if isInvalid(decision) {
		return nil
	}

	prefix, err := decisionPrefix(decision)
	if err != nil {
		return err
	}
	location := decisionLocation{prefix: prefix, key: keyForDecision(decision)}

	s.mu.Lock()
	defer s.mu.Unlock()

	if previous, ok := s.byID[decision.ID]; decision.ID != 0 && ok && previous != location {
		if err := s.removeLocked(previous); err != nil {
			return err
		}
	}

	bucket := s.buckets[prefix]
	if bucket == nil {
		bucket = &decisionBucket{decisions: make(map[decisionKey]*models.Decision)}
		if err := s.index.AddCIDR(prefix, bucket); err != nil {
			return err
		}
		s.buckets[prefix] = bucket
	}
	if previous := bucket.decisions[location.key]; previous != nil {
		delete(s.byID, previous.ID)
	} else {
		s.count++
		bucket.order = append(bucket.order, location.key)
	}
	// LAPI emits the effective member of each group. Equal-until members are
	// ordered by ascending ID, so replacing the group also follows that order.
	bucket.decisions[location.key] = decision
	if decision.ID != 0 {
		s.byID[decision.ID] = location
	}
	return nil
}

func (s *store) delete(decision *models.Decision) error {
	if decision == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A complete tombstone removes the effective group even when its ID is
	// different. LAPI suppresses its tombstone while any group member is active.
	if !isInvalid(decision) {
		prefix, err := decisionPrefix(decision)
		if err != nil {
			return err
		}
		return s.removeLocked(decisionLocation{prefix: prefix, key: keyForDecision(decision)})
	}
	// ID-only deletions address only the member currently retained. A delayed
	// deletion for an ID superseded by a later stream update is harmless.
	if decision.Scope == nil && decision.Type == nil && decision.Value == nil {
		if location, ok := s.byID[decision.ID]; decision.ID != 0 && ok {
			return s.removeLocked(location)
		}
	}
	return nil
}

func (s *store) removeLocked(location decisionLocation) error {
	bucket := s.buckets[location.prefix]
	if bucket == nil {
		return nil
	}
	decision := bucket.decisions[location.key]
	if decision == nil {
		return nil
	}
	delete(bucket.decisions, location.key)
	bucket.order = slices.DeleteFunc(bucket.order, func(key decisionKey) bool { return key == location.key })
	delete(s.byID, decision.ID)
	s.count--
	if len(bucket.decisions) == 0 {
		if _, err := s.index.RemoveCIDR(location.prefix); err != nil {
			return err
		}
		delete(s.buckets, location.prefix)
	}
	return nil
}

func (s *store) get(key netip.Addr) (*models.Decision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	buckets, err := s.index.Get(key)
	if err != nil {
		return nil, err
	}

	// an IP can exist in multiple networks (CIDR ranges), so there can be
	// multiple Decisions to act upon. Only one of them can be served, so the
	// strictest one is selected; see selectDecision.

	decisions := make([]*models.Decision, 0, len(buckets))
	for _, bucket := range buckets {
		// Preserve the existing selector's first-seen tie behavior. Updating a
		// group's effective member keeps its insertion position in the bucket.
		for _, key := range bucket.order {
			decisions = append(decisions, bucket.decisions[key])
		}
	}
	return selectDecision(decisions), nil
}

// Len counts effective semantic groups, including groups sharing one prefix.
func (s *store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// activeDecisionSnapshot releases the store lock before metrics are published.
func (s *store) activeDecisionSnapshot() []metrics.ActiveDecision {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]metrics.ActiveDecision, 0, s.count)
	for prefix, bucket := range s.buckets {
		for _, decision := range bucket.decisions {
			result = append(result, metrics.ActiveDecision{
				Origin: stringValue(decision.Origin),
				IPv6:   prefix.Addr().Is6(),
			})
		}
	}
	return result
}

func keyForDecision(decision *models.Decision) decisionKey {
	return decisionKey{scope: *decision.Scope, typ: *decision.Type, value: *decision.Value}
}

// decisionPrefix canonicalizes the index while retaining the exact wire key.
func decisionPrefix(decision *models.Decision) (netip.Prefix, error) {
	switch *decision.Scope {
	case "Ip":
		ip, err := parseIP(*decision.Value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return ip.Prefix(ip.BitLen())
	case "Range":
		prefix, err := netip.ParsePrefix(*decision.Value)
		return prefix.Masked(), err
	default:
		return netip.Prefix{}, fmt.Errorf("got unhandled scope: %s", *decision.Scope)
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// parseIP parses a value
func parseIP(value string) (netip.Addr, error) {
	var err error
	var ip netip.Addr
	ip, err = netip.ParseAddr(value)
	if err != nil || !ip.IsValid() {
		// try parsing as CIDR instead as fallback
		prf, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Addr{}, err
		}
		// expect all bits to be ones for an IP; otherwise this is probably a range
		ones, bits := prf.Bits(), prf.Addr().BitLen()
		if ones != bits {
			return netip.Addr{}, fmt.Errorf("%s seems to be a range instead of an IP", value)
		}
		ip = prf.Addr()
	}
	return ip, nil
}

// isInvalid determines if a *models.Decision struct is
// valid, meaning that it's not pointing to nil and has a
// Scope, Value and Type set, the minimum required to operate
func isInvalid(d *models.Decision) bool {
	if d == nil {
		return true
	}

	if d.Scope == nil {
		return true
	}

	if d.Value == nil {
		return true
	}

	if d.Type == nil {
		return true
	}

	return false
}
