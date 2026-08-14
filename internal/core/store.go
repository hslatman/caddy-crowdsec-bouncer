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
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/hslatman/ipstore"
)

// store retains the historical store.store access used by Core while allowing
// more than one decision to exist at an exact IP or prefix.
type store struct {
	store *decisionStore
}

type decisionStore struct {
	mu       sync.RWMutex
	prefixes *ipstore.Store[*decisionBucket]
	buckets  map[netip.Prefix]*decisionBucket
	byID     map[int64]decisionLocation
	count    int
	now      func() time.Time
}

type decisionBucket struct {
	decisions map[decisionKey]*storedDecision
}

// decisionKey mirrors the semantic key used by LAPI's default decision stream.
// LAPI emits only the longest-lived decision for an exact scope/type/value
// tuple, so additions replace that tuple and tombstones remove it regardless
// of which effective decision ID was most recently observed.
type decisionKey struct {
	scope string
	typ   string
	value string
}

type decisionLocation struct {
	prefix netip.Prefix
	key    decisionKey
}

type storedDecision struct {
	decision *models.Decision
	expires  time.Time
}

type decisionCandidate struct {
	decision *models.Decision
	prefix   netip.Prefix
	expires  time.Time
}

func newStore() *store {
	return newStoreWithClock(time.Now)
}

func newStoreWithClock(now func() time.Time) *store {
	if now == nil {
		now = time.Now
	}

	return &store{
		store: &decisionStore{
			prefixes: ipstore.New[*decisionBucket](),
			buckets:  make(map[netip.Prefix]*decisionBucket),
			byID:     make(map[int64]decisionLocation),
			now:      now,
		},
	}
}

func (s *store) add(decision *models.Decision) error {
	if err := validateStoredDecision(decision); err != nil {
		return err
	}

	prefix, err := decisionPrefix(decision)
	if err != nil {
		return err
	}

	return s.store.add(prefix, decision)
}

func (s *decisionStore) add(prefix netip.Prefix, decision *models.Decision) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := keyForDecision(decision)
	location := decisionLocation{prefix: prefix, key: key}

	// A repeated ID is an update. Remove its previous representation first,
	// including when the decision moved to a different target.
	if decision.ID != 0 {
		if oldLocation, ok := s.byID[decision.ID]; ok && oldLocation != location {
			if err := s.removeByKeyLocked(oldLocation.prefix, oldLocation.key); err != nil {
				return err
			}
		}
	}

	bucket, ok := s.buckets[prefix]
	if !ok {
		bucket = &decisionBucket{
			decisions: make(map[decisionKey]*storedDecision),
		}
		if err := s.prefixes.AddCIDR(prefix, bucket); err != nil {
			return err
		}
		s.buckets[prefix] = bucket
	}

	if previous, exists := bucket.decisions[key]; exists {
		if previous.decision.ID != 0 {
			delete(s.byID, previous.decision.ID)
		}
	} else {
		s.count++
	}
	bucket.decisions[key] = &storedDecision{
		decision: decision,
		expires:  decisionExpiration(decision, s.now()),
	}

	if decision.ID != 0 {
		s.byID[decision.ID] = location
	}

	return nil
}

func (s *store) delete(decision *models.Decision) error {
	if decision == nil {
		return errors.New("decision is nil")
	}
	if decision.ID < 0 {
		return fmt.Errorf("decision ID must not be negative: %d", decision.ID)
	}

	// Stream tombstones carry the semantic target. Remove that effective key,
	// even when its ID differs from the last addition: default LAPI streaming
	// suppresses tombstones while another member of the tuple remains active.
	if nonEmpty(decision.Scope) || nonEmpty(decision.Value) || nonEmpty(decision.Type) {
		if err := validateStoredDecision(decision); err != nil {
			return err
		}
		prefix, err := decisionPrefix(decision)
		if err != nil {
			return err
		}
		return s.store.deleteByKey(prefix, keyForDecision(decision))
	}

	if decision.ID != 0 {
		return s.store.deleteByID(decision.ID)
	}

	return errors.New("decision deletion requires an ID or semantic target")
}

func (s *decisionStore) deleteByID(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	location, ok := s.byID[id]
	if !ok {
		return nil
	}

	return s.removeByKeyLocked(location.prefix, location.key)
}

func (s *decisionStore) deleteByKey(prefix netip.Prefix, key decisionKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.removeByKeyLocked(prefix, key)
}

func (s *decisionStore) removeByKeyLocked(prefix netip.Prefix, key decisionKey) error {
	bucket, ok := s.buckets[prefix]
	if !ok {
		return nil
	}

	stored, ok := bucket.decisions[key]
	if !ok {
		return nil
	}

	delete(bucket.decisions, key)
	if stored.decision.ID != 0 {
		delete(s.byID, stored.decision.ID)
	}
	s.count--

	if len(bucket.decisions) == 0 {
		_, err := s.prefixes.RemoveCIDR(prefix)
		if err == nil {
			delete(s.buckets, prefix)
		}
		return err
	}

	return nil
}

func (s *store) get(key netip.Addr) (*models.Decision, error) {
	if !key.IsValid() {
		return nil, errors.New("lookup address is invalid")
	}

	candidates, now, err := s.store.get(key)
	if err != nil {
		return nil, err
	}

	selected, err := selectDecisionCandidate(key, candidates)
	if err != nil || selected == nil {
		return nil, err
	}

	return decisionAt(selected, now), nil
}

func (s *decisionStore) get(key netip.Addr) ([]*decisionCandidate, time.Time, error) {
	// Request lookups must not run global expiration maintenance: production
	// stores commonly contain tens of thousands of decisions. Expired matches
	// are filtered below, while stream, count, and metrics paths reclaim them.
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	buckets, err := s.prefixes.Get(key)
	if err != nil {
		return nil, now, err
	}

	candidates := make([]*decisionCandidate, 0, len(buckets))
	for _, bucket := range buckets {
		candidates = bucket.appendActive(candidates, now)
	}

	return candidates, now, nil
}

func (b *decisionBucket) appendActive(candidates []*decisionCandidate, now time.Time) []*decisionCandidate {
	for _, stored := range b.decisions {
		if !stored.expires.IsZero() && !stored.expires.After(now) {
			continue
		}
		candidates = append(candidates, &decisionCandidate{
			decision: stored.decision,
			expires:  stored.expires,
		})
	}

	return candidates
}

// Len reports decisions, not occupied prefixes. This keeps
// Core.NumberOfActiveDecisions meaningful when multiple decisions share a
// target.
func (s *decisionStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.pruneExpiredLocked(s.now())

	return s.count
}

// metricsStore adapts the multi-value store to the metrics provider's current
// single-value ipstore API. Synthetic keys are safe here: that provider only
// inspects the address family and decision origin.
func (s *store) metricsStore() *ipstore.Store[*models.Decision] {
	return s.store.metricsStore()
}

func (s *decisionStore) metricsStore() *ipstore.Store[*models.Decision] {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.pruneExpiredLocked(s.now())

	result := ipstore.New[*models.Decision]()
	var ipv4Index uint32
	var ipv6Index uint64

	for prefix, bucket := range s.buckets {
		for _, stored := range bucket.decisions {
			metricDecision := decisionForMetrics(stored.decision)
			if prefix.Addr().Is4() {
				addr := netip.AddrFrom4([4]byte{
					byte(ipv4Index >> 24),
					byte(ipv4Index >> 16),
					byte(ipv4Index >> 8),
					byte(ipv4Index),
				})
				_ = result.Add(addr, metricDecision)
				ipv4Index++
				continue
			}

			var raw [16]byte
			raw[8] = byte(ipv6Index >> 56)
			raw[9] = byte(ipv6Index >> 48)
			raw[10] = byte(ipv6Index >> 40)
			raw[11] = byte(ipv6Index >> 32)
			raw[12] = byte(ipv6Index >> 24)
			raw[13] = byte(ipv6Index >> 16)
			raw[14] = byte(ipv6Index >> 8)
			raw[15] = byte(ipv6Index)
			_ = result.Add(netip.AddrFrom16(raw), metricDecision)
			ipv6Index++
		}
	}

	return result
}

func (s *store) pruneExpired() (int, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	return s.store.pruneExpiredLocked(s.store.now())
}

func (s *decisionStore) pruneExpiredLocked(now time.Time) (int, error) {
	type expiredDecision struct {
		prefix netip.Prefix
		key    decisionKey
	}

	expired := make([]expiredDecision, 0)
	for prefix, bucket := range s.buckets {
		for key, stored := range bucket.decisions {
			if !stored.expires.IsZero() && !stored.expires.After(now) {
				expired = append(expired, expiredDecision{prefix: prefix, key: key})
			}
		}
	}

	for _, item := range expired {
		if err := s.removeByKeyLocked(item.prefix, item.key); err != nil {
			return 0, err
		}
	}

	return len(expired), nil
}

func decisionExpiration(decision *models.Decision, receivedAt time.Time) time.Time {
	if decision == nil || decision.Duration == nil {
		return time.Time{}
	}
	duration, err := time.ParseDuration(strings.TrimSpace(*decision.Duration))
	if err != nil || duration <= 0 {
		// Malformed metadata must not silently turn a blocking decision into an
		// allow. Keep it until LAPI sends a tombstone instead.
		return time.Time{}
	}
	return receivedAt.Add(duration)
}

// selectDecision is shared by streaming and live lookups. Higher remediation
// priority wins before prefix specificity; remaining ties use stable decision
// metadata so API and map iteration order cannot change the result.
func selectDecision(ip netip.Addr, decisions []*models.Decision) (*models.Decision, error) {
	candidates := make([]*decisionCandidate, 0, len(decisions))
	for _, decision := range decisions {
		candidates = append(candidates, &decisionCandidate{decision: decision})
	}

	selected, err := selectDecisionCandidate(ip, candidates)
	if err != nil || selected == nil {
		return nil, err
	}

	return selected.decision, nil
}

func selectDecisionCandidate(ip netip.Addr, candidates []*decisionCandidate) (*decisionCandidate, error) {
	if !ip.IsValid() {
		return nil, errors.New("lookup address is invalid")
	}

	groups := make(map[decisionKey]*decisionCandidate)
	var firstInvalid error
	for i, input := range candidates {
		var decision *models.Decision
		if input != nil {
			decision = input.decision
		}
		if err := validateStoredDecision(decision); err != nil {
			if firstInvalid == nil {
				firstInvalid = fmt.Errorf("invalid decision at index %d: %w", i, err)
			}
			continue
		}

		prefix, err := decisionPrefix(decision)
		if err != nil {
			if firstInvalid == nil {
				firstInvalid = fmt.Errorf("invalid decision at index %d: %w", i, err)
			}
			continue
		}
		if !prefix.Contains(ip) {
			continue
		}

		candidate := input
		candidate.prefix = prefix
		group := keyForDecision(decision)
		if current := groups[group]; current == nil || groupCandidatePrecedes(candidate, current) {
			groups[group] = candidate
		}
	}

	var selected *decisionCandidate
	for _, candidate := range groups {
		if selected == nil || candidatePrecedes(candidate, selected) {
			selected = candidate
		}
	}

	if selected != nil && (firstInvalid == nil || remediationPriority(*selected.decision.Type) == 3) {
		return selected, nil
	}
	if firstInvalid != nil {
		return nil, firstInvalid
	}

	return nil, nil
}

func candidatePrecedes(a, b *decisionCandidate) bool {
	aPriority := remediationPriority(*a.decision.Type)
	bPriority := remediationPriority(*b.decision.Type)
	if aPriority != bPriority {
		return aPriority > bPriority
	}

	if a.prefix.Bits() != b.prefix.Bits() {
		return a.prefix.Bits() > b.prefix.Bits()
	}

	if lifetimeComparison := compareCandidateLifetime(a, b); lifetimeComparison != 0 {
		return lifetimeComparison > 0
	}

	if a.decision.ID != b.decision.ID {
		return a.decision.ID < b.decision.ID
	}

	return stableDecisionKey(a.decision) < stableDecisionKey(b.decision)
}

func groupCandidatePrecedes(a, b *decisionCandidate) bool {
	if lifetimeComparison := compareCandidateLifetime(a, b); lifetimeComparison != 0 {
		return lifetimeComparison > 0
	}
	if a.decision.ID != b.decision.ID {
		// LAPI orders stream results by ascending ID. Its longest-decision
		// predicate uses a strict greater-than comparison, so equal-until group
		// members can both be emitted and the stream upsert ends on the larger ID.
		return a.decision.ID > b.decision.ID
	}
	return stableDecisionKey(a.decision) < stableDecisionKey(b.decision)
}

// compareCandidateLifetime returns 1 when a outlives b, -1 when b outlives a,
// and 0 when their usable lifetime metadata is equal. Stored candidates carry
// an absolute local expiry; live candidates carry LAPI's remaining Duration.
func compareCandidateLifetime(a, b *decisionCandidate) int {
	aExpiryValid := !a.expires.IsZero()
	bExpiryValid := !b.expires.IsZero()
	if aExpiryValid || bExpiryValid {
		// LAPI serializes remaining duration at one-second precision. Ignore
		// sub-second skew introduced while processing members of one response.
		aExpiry := a.expires.Round(time.Second)
		bExpiry := b.expires.Round(time.Second)
		switch {
		case aExpiryValid && !bExpiryValid:
			return 1
		case !aExpiryValid && bExpiryValid:
			return -1
		case aExpiry.After(bExpiry):
			return 1
		case aExpiry.Before(bExpiry):
			return -1
		default:
			return 0
		}
	}

	aDuration, aDurationValid := parsedDecisionDuration(a.decision)
	bDuration, bDurationValid := parsedDecisionDuration(b.decision)
	switch {
	case aDurationValid && !bDurationValid:
		return 1
	case !aDurationValid && bDurationValid:
		return -1
	case aDuration > bDuration:
		return 1
	case aDuration < bDuration:
		return -1
	default:
		return 0
	}
}

func decisionAt(candidate *decisionCandidate, now time.Time) *models.Decision {
	if candidate == nil || candidate.decision == nil || candidate.expires.IsZero() {
		if candidate == nil {
			return nil
		}
		return candidate.decision
	}

	clone := *candidate.decision
	remaining := candidate.expires.Sub(now).Round(time.Second).String()
	clone.Duration = &remaining

	return &clone
}

func parsedDecisionDuration(decision *models.Decision) (time.Duration, bool) {
	if decision == nil || decision.Duration == nil {
		return 0, false
	}
	duration, err := time.ParseDuration(strings.TrimSpace(*decision.Duration))
	return duration, err == nil && duration > 0
}

func remediationPriority(typ string) int {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "captcha":
		return 2
	case "throttle":
		return 1
	case "ban":
		return 3
	default:
		// Existing response handling converts unknown actions to a ban. Keep
		// the selector equally fail-closed.
		return 3
	}
}

func stableDecisionKey(decision *models.Decision) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(stringValue(decision.Type))),
		strings.ToLower(strings.TrimSpace(stringValue(decision.Scope))),
		strings.TrimSpace(stringValue(decision.Value)),
		strings.TrimSpace(stringValue(decision.Origin)),
		strings.TrimSpace(stringValue(decision.Scenario)),
		strings.TrimSpace(stringValue(decision.Duration)),
		decision.UUID,
	}, "\x00")
}

func keyForDecision(decision *models.Decision) decisionKey {
	return decisionKey{
		scope: *decision.Scope,
		typ:   *decision.Type,
		value: *decision.Value,
	}
}

func decisionPrefix(decision *models.Decision) (netip.Prefix, error) {
	scope := strings.ToLower(strings.TrimSpace(*decision.Scope))
	value := strings.TrimSpace(*decision.Value)

	switch scope {
	case "ip":
		ip, err := parseIP(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return ip.Prefix(ip.BitLen())
	case "range":
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	default:
		return netip.Prefix{}, fmt.Errorf("got unhandled scope: %s", *decision.Scope)
	}
}

// parseIP parses a value and accepts host-length CIDR notation as a fallback.
func parseIP(value string) (netip.Addr, error) {
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.IsValid() {
		prefix, prefixErr := netip.ParsePrefix(value)
		if prefixErr != nil {
			return netip.Addr{}, prefixErr
		}
		// Expect all bits to be ones for an IP; otherwise this is a range.
		if prefix.Bits() != prefix.Addr().BitLen() {
			return netip.Addr{}, fmt.Errorf("%s seems to be a range instead of an IP", value)
		}
		ip = prefix.Addr()
	}

	return ip, nil
}

func validateStoredDecision(decision *models.Decision) error {
	if err := validateDecisionTarget(decision); err != nil {
		return err
	}
	if decision.ID < 0 {
		return fmt.Errorf("decision ID must not be negative: %d", decision.ID)
	}
	if !nonEmpty(decision.Type) {
		return errors.New("decision type is missing")
	}

	return nil
}

func validateDecisionTarget(decision *models.Decision) error {
	if decision == nil {
		return errors.New("decision is nil")
	}
	if !nonEmpty(decision.Scope) {
		return errors.New("decision scope is missing")
	}
	if !nonEmpty(decision.Value) {
		return errors.New("decision value is missing")
	}

	return nil
}

func nonEmpty(value *string) bool {
	return value != nil && strings.TrimSpace(*value) != ""
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func decisionForMetrics(decision *models.Decision) *models.Decision {
	if nonEmpty(decision.Origin) {
		return decision
	}

	clone := *decision
	origin := "unknown"
	clone.Origin = &origin

	return &clone
}
