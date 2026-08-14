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
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	duration := "120s"
	source := "cscli"
	scenario := "manual ban ..."
	scopeIP := "Ip"
	scopeRange := "Range"
	typ := "ban"
	value1 := "127.0.0.1"
	value2 := "127.0.0.2"
	value3 := "10.0.0.1/24"
	value4 := "128.0.0.1/32"
	value5 := "129.0.0.1/24"

	d1 := &models.Decision{
		Duration: &duration,
		ID:       1,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeIP,
		Type:     &typ,
		Value:    &value1,
	}

	d2 := &models.Decision{
		Duration: &duration,
		ID:       2,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeIP,
		Type:     &typ,
		Value:    &value2,
	}

	d3 := &models.Decision{
		Duration: &duration,
		ID:       3,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeRange,
		Type:     &typ,
		Value:    &value3,
	}

	d4 := &models.Decision{
		Duration: &duration,
		ID:       4,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeIP,
		Type:     &typ,
		Value:    &value4, // ip in range notation
	}

	d5 := &models.Decision{
		Duration: &duration,
		ID:       5,
		Origin:   &source,
		Scenario: &scenario,
		Scope:    &scopeIP, // IP scope
		Type:     &typ,
		Value:    &value5, // range
	}

	s := newStore()
	err := s.add(d1)
	require.NoError(t, err)
	err = s.add(d2)
	require.NoError(t, err)
	err = s.add(d3)
	require.NoError(t, err)
	err = s.add(d4)
	require.NoError(t, err)
	err = s.add(d5)
	require.Error(t, err)
	require.Equal(t, 4, s.store.Len())

	ip1 := netip.MustParseAddr(value1)
	r1, err := s.get(ip1)
	require.NoError(t, err)
	require.NotNil(t, r1)
	require.Equal(t, value1, *r1.Value)

	err = s.delete(d1)
	require.NoError(t, err)

	err = s.delete(d3)
	require.NoError(t, err)

	r1, err = s.get(ip1)
	require.NoError(t, err)
	require.Nil(t, r1)
}

func TestStoreRetainsAndSelectsMultipleDecisionsForOneTarget(t *testing.T) {
	tests := []struct {
		name     string
		types    []string
		expected string
	}{
		{
			name:     "ban takes precedence over captcha and throttle",
			types:    []string{"throttle", "captcha", "ban"},
			expected: "ban",
		},
		{
			name:     "unknown action remains fail closed",
			types:    []string{"captcha", "custom-remediation"},
			expected: "custom-remediation",
		},
		{
			name:     "captcha takes precedence over throttle",
			types:    []string{"throttle", "captcha"},
			expected: "captcha",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			orders := [][]string{test.types, slices.Clone(test.types)}
			slices.Reverse(orders[1])

			for _, order := range orders {
				s := newStore()
				for index, typ := range order {
					require.NoError(t, s.add(testDecision(int64(index+1), "Ip", "192.0.2.10", typ)))
				}

				require.Equal(t, len(test.types), s.store.Len())
				selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
				require.NoError(t, err)
				require.NotNil(t, selected)
				require.Equal(t, test.expected, *selected.Type)
			}
		})
	}
}

func TestStoreSelectsAcrossOverlappingIPAndRanges(t *testing.T) {
	s := newStore()
	rangeCaptcha := testDecision(1, "Range", "192.0.2.99/24", "captcha")
	ipThrottle := testDecision(2, "Ip", "192.0.2.10", "throttle")
	rangeBan := testDecision(3, "Range", "192.0.0.0/16", "ban")
	ipBan := testDecision(4, "Ip", "192.0.2.10", "ban")

	for _, decision := range []*models.Decision{rangeCaptcha, ipThrottle, rangeBan, ipBan} {
		require.NoError(t, s.add(decision))
	}

	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, ipBan, selected, "the more-specific decision should break equal-action ties")

	require.NoError(t, s.delete(ipBan))
	selected, err = s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, rangeBan, selected, "action priority should beat prefix specificity")

	require.NoError(t, s.delete(rangeBan))
	selected, err = s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, rangeCaptcha, selected, "captcha should beat a more-specific throttle")
}

func TestStoreKeepsOverlappingPrefixBucketsIndependent(t *testing.T) {
	s := newStore()
	rangeDecision := testDecision(1, "Range", "192.0.2.0/24", "captcha")
	ipDecision := testDecision(2, "Ip", "192.0.2.10", "throttle")
	require.NoError(t, s.add(rangeDecision))
	require.NoError(t, s.add(ipDecision))

	rangePrefix := netip.MustParsePrefix("192.0.2.0/24")
	ipPrefix := netip.MustParsePrefix("192.0.2.10/32")
	require.NotSame(t, s.store.buckets[rangePrefix], s.store.buckets[ipPrefix])
	require.Equal(t, 2, s.metricsStore().Len(), "metrics must not duplicate decisions across overlapping prefixes")

	require.NoError(t, s.delete(rangeDecision))
	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, ipDecision, selected)
	require.Equal(t, 1, s.metricsStore().Len())
}

func TestStoreDeleteUsesDecisionID(t *testing.T) {
	t.Run("only matching ID is removed", func(t *testing.T) {
		s := newStore()
		captcha := testDecision(10, "Ip", "192.0.2.10", "captcha")
		ban := testDecision(11, "Ip", "192.0.2.10", "ban")
		require.NoError(t, s.add(captcha))
		require.NoError(t, s.add(ban))

		require.NoError(t, s.delete(&models.Decision{ID: captcha.ID}))
		require.Equal(t, 1, s.store.Len())

		selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
		require.NoError(t, err)
		requireDecisionIdentity(t, ban, selected)
	})

	t.Run("complete tombstone removes the effective semantic group", func(t *testing.T) {
		s := newStore()
		stored := testDecision(10, "Ip", "192.0.2.10", "ban")
		require.NoError(t, s.add(stored))

		tombstone := testDecision(999, "Ip", "192.0.2.10", "ban")
		require.NoError(t, s.delete(tombstone))
		require.Zero(t, s.store.Len())
	})

	t.Run("same ID updates and can move target", func(t *testing.T) {
		s := newStore()
		original := testDecision(10, "Ip", "192.0.2.10", "captcha")
		updated := testDecision(10, "Ip", "192.0.2.11", "ban")
		require.NoError(t, s.add(original))
		require.NoError(t, s.add(updated))
		require.Equal(t, 1, s.store.Len())

		selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
		require.NoError(t, err)
		require.Nil(t, selected)

		selected, err = s.get(netip.MustParseAddr("192.0.2.11"))
		require.NoError(t, err)
		requireDecisionIdentity(t, updated, selected)
	})

	t.Run("new LAPI decision supersedes the same target and remediation", func(t *testing.T) {
		s := newStore()
		oldCaptcha := testDecision(10, "Ip", "192.0.2.10", "captcha")
		newCaptcha := testDecision(11, "Ip", "192.0.2.10", "captcha")
		ban := testDecision(12, "Ip", "192.0.2.10", "ban")

		require.NoError(t, s.add(oldCaptcha))
		require.NoError(t, s.add(ban))
		require.NoError(t, s.add(newCaptcha))
		require.Equal(t, 2, s.store.Len(), "different remediation types must remain independent")

		require.NoError(t, s.delete(&models.Decision{ID: oldCaptcha.ID}))
		selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
		require.NoError(t, err)
		requireDecisionIdentity(t, ban, selected, "a delayed tombstone for the superseded ID must be harmless")

		require.NoError(t, s.delete(ban))
		selected, err = s.get(netip.MustParseAddr("192.0.2.10"))
		require.NoError(t, err)
		requireDecisionIdentity(t, newCaptcha, selected)

		require.NoError(t, s.delete(newCaptcha))
		require.Zero(t, s.store.Len())
	})
}

func TestStoreDeleteWithoutID(t *testing.T) {
	t.Run("unique semantic match", func(t *testing.T) {
		s := newStore()
		stored := testDecision(0, "Range", "192.0.2.99/24", "captcha")
		require.NoError(t, s.add(stored))

		tombstone := testDecision(0, "Range", "192.0.2.99/24", "captcha")
		require.NoError(t, s.delete(tombstone))
		require.Zero(t, s.store.Len())
	})

	t.Run("same stream group is upserted independent of origin", func(t *testing.T) {
		s := newStore()
		first := testDecision(0, "Ip", "192.0.2.10", "ban")
		*first.Scenario = "first ID-less source"
		second := testDecision(0, "Ip", "192.0.2.10", "ban")
		*second.Origin = "CAPI"
		*second.Scenario = "second ID-less source"
		require.NoError(t, s.add(first))
		require.NoError(t, s.add(second))
		require.Equal(t, 1, s.store.Len())
		metricsStore := s.metricsStore()
		require.Equal(t, 1, metricsStore.Len(), "metrics must count the effective group, not every historical member")
		for _, metricDecision := range metricsStore.All() {
			require.Equal(t, "CAPI", stringValue(metricDecision.Origin))
		}

		tombstone := testDecision(0, "Ip", "192.0.2.10", "ban")
		require.NoError(t, s.delete(tombstone))
		require.Zero(t, s.store.Len())
	})

	t.Run("semantic tombstone preserves other remediation groups", func(t *testing.T) {
		s := newStore()
		ban := testDecision(0, "Ip", "192.0.2.10", "ban")
		captcha := testDecision(3, "Ip", "192.0.2.10", "captcha")
		require.NoError(t, s.add(ban))
		require.NoError(t, s.add(captcha))

		tombstone := testDecision(0, "ip", "192.0.2.10", "ban")
		*tombstone.Scope = "Ip"
		require.NoError(t, s.delete(tombstone))
		require.Equal(t, 1, s.store.Len())

		selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
		require.NoError(t, err)
		requireDecisionIdentity(t, captcha, selected)
	})
}

func TestSelectDecisionIsOrderIndependentForLiveResults(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	decisions := []*models.Decision{
		testDecision(30, "Range", "192.0.2.0/24", "throttle"),
		testDecision(20, "Range", "192.0.2.0/24", "captcha"),
		testDecision(10, "Range", "192.0.0.0/16", "ban"),
	}

	selected, err := selectDecision(ip, decisions)
	require.NoError(t, err)
	require.EqualValues(t, 10, selected.ID)

	slices.Reverse(decisions)
	selected, err = selectDecision(ip, decisions)
	require.NoError(t, err)
	require.EqualValues(t, 10, selected.ID)

	unrelated := testDecision(1, "Ip", "198.51.100.1", "ban")
	selected, err = selectDecision(ip, []*models.Decision{unrelated})
	require.NoError(t, err)
	require.Nil(t, selected)
}

func TestSelectDecisionUsesLongestLiveDecisionWithinGroup(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	shorter := testDecision(1, "Ip", ip.String(), "captcha")
	longer := testDecision(2, "Ip", ip.String(), "captcha")
	*shorter.Duration = "1m"
	*longer.Duration = "2m"

	for _, decisions := range [][]*models.Decision{{shorter, longer}, {longer, shorter}} {
		selected, err := selectDecision(ip, decisions)
		require.NoError(t, err)
		require.Same(t, longer, selected)
	}
}

func TestSelectDecisionMatchesStreamUpsertForEqualLongestGroupMembers(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	lowerID := testDecision(10, "Ip", ip.String(), "captcha")
	higherID := testDecision(11, "Ip", ip.String(), "captcha")
	*lowerID.Origin = "first"
	*higherID.Origin = "second"

	// LAPI's longest-decision predicate is strict. Members with the same Until
	// can therefore both be returned by the stream, ordered by ascending ID;
	// the semantic upsert ends on the higher ID.
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	stream := newStoreWithClock(func() time.Time { return now })
	require.NoError(t, stream.add(lowerID))
	require.NoError(t, stream.add(higherID))
	streamSelected, err := stream.get(ip)
	require.NoError(t, err)
	requireDecisionIdentity(t, higherID, streamSelected)

	for _, live := range [][]*models.Decision{{lowerID, higherID}, {higherID, lowerID}} {
		liveSelected, err := selectDecision(ip, live)
		require.NoError(t, err)
		require.Same(t, higherID, liveSelected)
		requireDecisionIdentity(t, streamSelected, liveSelected)
	}
}

func TestLiveAndDefaultStreamSelectTheSameEffectiveDecision(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	shortCaptcha := testDecision(10, "Ip", ip.String(), "captcha")
	longCaptcha := testDecision(11, "Ip", ip.String(), "captcha")
	throttle := testDecision(12, "Range", "192.0.2.0/24", "throttle")
	*shortCaptcha.Duration = "1m"
	*longCaptcha.Duration = "2m"
	*throttle.Duration = "3m"

	liveSelected, err := selectDecision(ip, []*models.Decision{shortCaptcha, throttle, longCaptcha})
	require.NoError(t, err)
	require.Same(t, longCaptcha, liveSelected)

	// The default stream emits only the longest member of an exact
	// scope/type/value group.
	stream := newStore()
	require.NoError(t, stream.add(longCaptcha))
	require.NoError(t, stream.add(throttle))
	streamSelected, err := stream.get(ip)
	require.NoError(t, err)
	requireDecisionIdentity(t, liveSelected, streamSelected)
}

func TestLiveAndStreamIgnoreSubsecondIngestionSkew(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	lowerID := testDecision(10, "Ip", ip.String(), "captcha")
	higherID := testDecision(11, "Range", "192.0.2.10/32", "captcha")

	liveSelected, err := selectDecision(ip, []*models.Decision{higherID, lowerID})
	require.NoError(t, err)
	require.Same(t, lowerID, liveSelected)

	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	stream := newStoreWithClock(func() time.Time { return now })
	require.NoError(t, stream.add(lowerID))
	now = now.Add(time.Millisecond)
	require.NoError(t, stream.add(higherID))

	streamSelected, err := stream.get(ip)
	require.NoError(t, err)
	requireDecisionIdentity(t, liveSelected, streamSelected)
}

func TestStoreKeepsExactLAPIGroupKeysIndependent(t *testing.T) {
	s := newStore()
	plainIP := testDecision(1, "Ip", "192.0.2.10", "captcha")
	cidrIP := testDecision(2, "Ip", "192.0.2.10/32", "captcha")
	rangeIP := testDecision(3, "Range", "192.0.2.10/32", "captcha")
	spacedIP := testDecision(4, "Ip", " 192.0.2.10 ", "captcha")
	lowercaseScope := testDecision(5, "ip", "192.0.2.10", "captcha")
	uppercaseType := testDecision(6, "Ip", "192.0.2.10", "CAPTCHA")
	for _, decision := range []*models.Decision{plainIP, cidrIP, rangeIP, spacedIP, lowercaseScope, uppercaseType} {
		require.NoError(t, s.add(decision))
	}
	require.Equal(t, 6, s.store.Len())

	require.NoError(t, s.delete(testDecision(99, "Ip", "192.0.2.10", "captcha")))
	require.Equal(t, 5, s.store.Len())
}

func TestStoreDoesNotExpireRoundedDurationEarly(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	s := newStoreWithClock(func() time.Time { return now })
	expiredMatch := testDecision(1, "Ip", "192.0.2.10", "captcha")
	*expiredMatch.Duration = time.Second.String()
	activeMatch := testDecision(2, "Range", "192.0.2.0/24", "throttle")
	*activeMatch.Duration = time.Minute.String()
	expiredUnrelated := testDecision(3, "Ip", "198.51.100.10", "ban")
	*expiredUnrelated.Duration = time.Second.String()

	require.NoError(t, s.add(expiredMatch))
	require.NoError(t, s.add(activeMatch))
	require.NoError(t, s.add(expiredUnrelated))
	require.Equal(t, 3, s.store.Len())

	now = now.Add(time.Second + lapiDurationRoundingTolerance - time.Nanosecond)
	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, expiredMatch, selected, "rounded duration must remain fail-closed through its uncertainty window")
	require.Equal(t, 3, s.store.count, "request lookup must not scan and mutate the whole store")

	now = now.Add(time.Nanosecond)
	selected, err = s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, activeMatch, selected, "an expired higher-priority action must not be enforced")
	require.Equal(t, 3, s.store.count, "request lookup must not scan and mutate the whole store")

	require.Equal(t, 1, s.store.Len(), "maintenance paths should physically remove expired decisions")
}

func TestStoreZeroRoundedDurationExpiresAfterTolerance(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	s := newStoreWithClock(func() time.Time { return now })
	decision := testDecision(1, "Ip", "192.0.2.10", "captcha")
	*decision.Duration = "0s"
	require.NoError(t, s.add(decision))

	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, decision, selected)
	require.Equal(t, "0s", stringValue(selected.Duration))

	now = now.Add(lapiDurationRoundingTolerance - time.Nanosecond)
	selected, err = s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, decision, selected)

	now = now.Add(time.Nanosecond)
	selected, err = s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	require.Nil(t, selected)
	require.Zero(t, s.store.Len(), "a valid zero duration must never become an unbounded local decision")
}

func TestStoreReturnsRemainingDurationWithoutMutatingStreamDecision(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	s := newStoreWithClock(func() time.Time { return now })
	decision := testDecision(1, "Ip", "192.0.2.10", "throttle")
	*decision.Duration = "2m"
	require.NoError(t, s.add(decision))

	now = now.Add(30 * time.Second)
	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, decision, selected)
	require.Equal(t, "1m30s", stringValue(selected.Duration))
	require.Equal(t, "2m", stringValue(decision.Duration), "lookup must not mutate a decision shared with the stream")

	now = now.Add(90 * time.Second)
	selected, err = s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, decision, selected, "the rounded duration remains active through the fail-closed tolerance")
	require.Equal(t, "0s", stringValue(selected.Duration))

	now = now.Add(lapiDurationRoundingTolerance)
	selected, err = s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	require.Nil(t, selected)
	require.Zero(t, s.store.Len())
}

func TestStoreKeepsMalformedDurationFailClosedUntilTombstone(t *testing.T) {
	now := time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC)
	s := newStoreWithClock(func() time.Time { return now })
	decision := testDecision(1, "Ip", "192.0.2.10", "ban")
	*decision.Duration = "invalid"
	require.NoError(t, s.add(decision))
	stored := s.store.buckets[netip.MustParsePrefix("192.0.2.10/32")].decisions[keyForDecision(decision)]
	require.True(t, stored.expires.IsZero(), "malformed duration must remain distinct from a valid zero duration")

	now = now.Add(24 * time.Hour)
	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	require.Same(t, decision, selected)
	require.NoError(t, s.delete(testDecision(2, "Ip", "192.0.2.10", "ban")))
	require.Zero(t, s.store.Len())
}

func TestStoreRejectsMalformedDecisions(t *testing.T) {
	valid := testDecision(1, "Ip", "192.0.2.10", "ban")

	tests := []struct {
		name     string
		decision *models.Decision
	}{
		{name: "nil decision"},
		{name: "empty decision", decision: &models.Decision{}},
		{name: "missing scope", decision: cloneDecision(valid, func(d *models.Decision) { d.Scope = nil })},
		{name: "missing value", decision: cloneDecision(valid, func(d *models.Decision) { d.Value = nil })},
		{name: "missing type", decision: cloneDecision(valid, func(d *models.Decision) { d.Type = nil })},
		{name: "negative ID", decision: cloneDecision(valid, func(d *models.Decision) { d.ID = -1 })},
		{name: "unsupported scope", decision: testDecision(1, "Country", "US", "ban")},
		{name: "invalid IP", decision: testDecision(1, "Ip", "not-an-ip", "ban")},
		{name: "range in IP scope", decision: testDecision(1, "Ip", "192.0.2.0/24", "ban")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newStore()
			require.Error(t, s.add(test.decision))
			require.Zero(t, s.store.Len())
		})
	}

	_, err := selectDecision(netip.MustParseAddr("192.0.2.10"), []*models.Decision{nil})
	require.Error(t, err)
	_, err = newStore().get(netip.Addr{})
	require.Error(t, err)
}

func TestStoreAcceptsOptionalDecisionMetadata(t *testing.T) {
	s := newStore()
	decision := testDecision(1, "Ip", "192.0.2.10", "ban")
	decision.Duration = nil
	decision.Origin = nil
	decision.Scenario = nil

	require.NoError(t, s.add(decision))
	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	require.Same(t, decision, selected)

	metricsStore := s.metricsStore()
	for _, metricDecision := range metricsStore.All() {
		require.NotNil(t, metricDecision.Origin)
		require.Equal(t, "unknown", *metricDecision.Origin)
		require.Nil(t, decision.Origin, "metrics adaptation must not mutate the stored decision")
	}
}

func TestSelectDecisionMalformedEntryCannotHideValidBan(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	validBan := testDecision(1, "Ip", ip.String(), "ban")
	malformed := &models.Decision{}

	selected, err := selectDecision(ip, []*models.Decision{malformed, validBan})
	require.NoError(t, err)
	require.Same(t, validBan, selected)

	_, err = selectDecision(ip, []*models.Decision{malformed})
	require.Error(t, err, "an entirely malformed response must not become an allow")
}

func TestMetricsStoreIncludesEveryDecisionAndAddressFamily(t *testing.T) {
	s := newStore()
	require.NoError(t, s.add(testDecision(1, "Ip", "192.0.2.10", "ban")))
	require.NoError(t, s.add(testDecision(2, "Ip", "192.0.2.10", "captcha")))
	require.NoError(t, s.add(testDecision(3, "Range", "2001:db8::/32", "ban")))

	metricsStore := s.metricsStore()
	require.Equal(t, 3, metricsStore.Len())

	var ipv4, ipv6 int
	for prefix := range metricsStore.All() {
		if prefix.Addr().Is4() {
			ipv4++
		} else {
			ipv6++
		}
	}
	require.Equal(t, 2, ipv4)
	require.Equal(t, 1, ipv6)
}

func TestStoreConcurrentAddLookupAndDelete(t *testing.T) {
	const count = 64
	s := newStore()
	errs := make(chan error, count)

	var wg sync.WaitGroup
	for id := 1; id <= count; id++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.add(testDecision(int64(id), "Ip", "192.0.2.10", "captcha"))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, 1, s.store.Len(), "LAPI exposes one effective decision per target and remediation")

	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	require.NotNil(t, selected)

	errs = make(chan error, count)
	for id := 1; id <= count; id++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.delete(&models.Decision{ID: int64(id)})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Zero(t, s.store.Len())
}

func TestStoreConcurrentLookupAndMaintenance(t *testing.T) {
	const (
		readers    = 32
		iterations = 100
	)

	s := newStore()
	expected := testDecision(1, "Range", "192.0.2.0/24", "ban")
	require.NoError(t, s.add(expected))

	errs := make(chan error, readers+1)
	var wg sync.WaitGroup
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
				if err != nil {
					errs <- err
					return
				}
				if selected == nil || selected.ID != expected.ID {
					errs <- fmt.Errorf("unexpected selected decision: %p", selected)
					return
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		decision := testDecision(2, "Ip", "198.51.100.10", "captcha")
		for range iterations {
			if err := s.add(decision); err != nil {
				errs <- err
				return
			}
			if err := s.delete(decision); err != nil {
				errs <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func testDecision(id int64, scope, value, typ string) *models.Decision {
	duration := "120s"
	origin := "cscli"
	scenario := fmt.Sprintf("test scenario %s", typ)

	return &models.Decision{
		Duration: &duration,
		ID:       id,
		Origin:   &origin,
		Scenario: &scenario,
		Scope:    &scope,
		Type:     &typ,
		Value:    &value,
	}
}

func cloneDecision(decision *models.Decision, mutate func(*models.Decision)) *models.Decision {
	clone := *decision
	mutate(&clone)
	return &clone
}

func requireDecisionIdentity(t *testing.T, expected, actual *models.Decision, msgAndArgs ...any) {
	t.Helper()
	require.NotNil(t, actual, msgAndArgs...)
	require.Equal(t, expected.ID, actual.ID, msgAndArgs...)
	require.Equal(t, stringValue(expected.Scope), stringValue(actual.Scope), msgAndArgs...)
	require.Equal(t, stringValue(expected.Type), stringValue(actual.Type), msgAndArgs...)
	require.Equal(t, stringValue(expected.Value), stringValue(actual.Value), msgAndArgs...)
	require.Equal(t, stringValue(expected.Origin), stringValue(actual.Origin), msgAndArgs...)
	require.Equal(t, stringValue(expected.Scenario), stringValue(actual.Scenario), msgAndArgs...)
}
