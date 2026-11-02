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
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/hslatman/ipstore"

	"github.com/hslatman/caddy-crowdsec-bouncer/internal/metrics"
)

const streamCacheExpiryInterval = time.Second

type decisionExpiry struct {
	decision  *models.Decision
	expiresAt time.Time
}

type store struct {
	mu      sync.Mutex
	store   *ipstore.Store[*models.Decision]
	entries map[netip.Prefix]decisionExpiry
	now     func() time.Time
}

func newStore() *store {
	return &store{
		store:   ipstore.New[*models.Decision](),
		entries: make(map[netip.Prefix]decisionExpiry),
		now:     time.Now,
	}
}

func (s *store) add(decision *models.Decision) error {
	prefix, err := decisionPrefix(decision)
	if err != nil {
		return err
	}
	if decision.ID <= 0 || decision.Type == nil || decision.Origin == nil || decision.Duration == nil {
		return errors.New("decision is missing required fields")
	}
	duration, err := time.ParseDuration(*decision.Duration)
	if err != nil || duration <= 0 {
		return errors.New("decision duration must be a valid positive duration")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	expiresAt := now.Add(duration)
	existing, found := s.entries[prefix]
	if found && existing.decision.ID == decision.ID && existing.expiresAt.Before(expiresAt) {
		// A duplicate stream response must not renew an existing decision.
		expiresAt = existing.expiresAt
	}
	if !now.Before(expiresAt) {
		return errors.New("decision has already expired locally")
	}

	// Keep fields consumed by matching, logging and response handling immutable
	// even if the caller reuses its model after insertion.
	stored := *decision
	scope, value := *decision.Scope, *decision.Value
	typ, origin, ttl := *decision.Type, *decision.Origin, *decision.Duration
	stored.Scope, stored.Value = &scope, &value
	stored.Type, stored.Origin, stored.Duration = &typ, &origin, &ttl
	if err := s.store.AddCIDR(prefix, &stored); err != nil {
		return err
	}
	s.entries[prefix] = decisionExpiry{decision: &stored, expiresAt: expiresAt}
	return nil
}

func (s *store) delete(decision *models.Decision) error {
	prefix, err := decisionPrefix(decision)
	if err != nil {
		return err
	}
	if decision.ID <= 0 {
		return errors.New("deleted decision is missing its ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.entries[prefix]; ok && entry.decision.ID == decision.ID {
		s.removeLocked(prefix)
	}
	return nil
}

func (s *store) get(key netip.Addr) (*models.Decision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	matches, err := s.store.Get(key)
	if err != nil {
		return nil, err
	}
	now := s.now()
	live := make([]*models.Decision, 0, len(matches))
	// Only matching prefixes are checked here, never the whole cache.
	// An expired specific entry must not hide another still-active match.
	for _, decision := range matches {
		prefix, err := decisionPrefix(decision)
		if err != nil {
			return nil, err
		}
		entry, ok := s.entries[prefix]
		if !ok {
			continue
		}
		if !now.Before(entry.expiresAt) {
			s.removeLocked(prefix)
			continue
		}
		live = append(live, entry.decision)
	}
	// Preserve the strictest-remediation policy among still-active matches.
	return selectDecision(live), nil
}

func (s *store) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(s.now())
	return len(s.entries)
}

func (s *store) expire() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expireLocked(s.now())
}

func (s *store) recordDecisionCounts(provider *metrics.Provider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(s.now())
	// ipstore.All returns a lazy iterator. Hold the cache lock throughout its
	// consumption so expiry and stream updates cannot mutate its backing tree.
	provider.RecalculateAndRecordDecisionCounts(s.store)
}

func (s *store) expireLocked(now time.Time) bool {
	expired := false
	for prefix, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			s.removeLocked(prefix)
			expired = true
		}
	}
	return expired
}

func (s *store) removeLocked(prefix netip.Prefix) {
	// ipstore v0.5.0 RemoveCIDR returns no error for a validated prefix.
	_, _ = s.store.RemoveCIDR(prefix)
	delete(s.entries, prefix)
}

func decisionPrefix(decision *models.Decision) (netip.Prefix, error) {
	if decision == nil || decision.Scope == nil || decision.Value == nil {
		return netip.Prefix{}, errors.New("decision is missing its scope or value")
	}
	switch *decision.Scope {
	case "Ip":
		ip, err := parseIP(*decision.Value)
		if err != nil {
			return netip.Prefix{}, errors.New("decision has an invalid IP value")
		}
		return ip.Prefix(ip.BitLen())
	case "Range":
		prefix, err := netip.ParsePrefix(*decision.Value)
		if err != nil {
			return netip.Prefix{}, errors.New("decision has an invalid range value")
		}
		return prefix.Masked(), nil
	default:
		return netip.Prefix{}, errors.New("decision has an unsupported scope")
	}
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
