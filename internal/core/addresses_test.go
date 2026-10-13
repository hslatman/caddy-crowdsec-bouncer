package core

import (
	"net/netip"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestDecisionLookupsMatchAddressRepresentations(t *testing.T) {
	for _, test := range []struct {
		name    string
		scope   string
		value   string
		matches []string
		misses  []string
	}{
		{
			name: "IPv4 address", scope: "Ip", value: "192.0.2.10",
			matches: []string{"192.0.2.10", "::ffff:192.0.2.10"},
			misses:  []string{"192.0.2.11", "2001:db8::1"},
		},
		{
			name: "mapped address", scope: "Ip", value: "::ffff:192.0.2.10",
			matches: []string{"192.0.2.10", "::ffff:c000:20a"},
			misses:  []string{"::ffff:192.0.2.11", "2001:db8::1"},
		},
		{
			name: "mapped host CIDR", scope: "Ip", value: "::ffff:c000:20a/128",
			matches: []string{"192.0.2.10", "::ffff:192.0.2.10"},
			misses:  []string{"192.0.2.11"},
		},
		{
			name: "IPv4 range", scope: "Range", value: "192.0.2.99/24",
			matches: []string{"192.0.2.0", "::ffff:192.0.2.255"},
			misses:  []string{"192.0.1.255", "::ffff:192.0.3.0", "2001:db8::1"},
		},
		{
			name: "mapped range", scope: "Range", value: "::ffff:192.0.2.99/120",
			matches: []string{"192.0.2.0", "::ffff:192.0.2.255"},
			misses:  []string{"192.0.1.255", "::ffff:192.0.3.0", "2001:db8::1"},
		},
		{
			name: "mapped host range", scope: "Range", value: "::ffff:192.0.2.10/128",
			matches: []string{"192.0.2.10", "::ffff:192.0.2.10"},
			misses:  []string{"192.0.2.11"},
		},
		{
			name: "mapped IPv4 default route", scope: "Range", value: "::ffff:0.0.0.0/96",
			matches: []string{"0.0.0.0", "::ffff:255.255.255.255"},
			misses:  []string{"::1", "2001:db8::1"},
		},
		{
			name: "native IPv6 address", scope: "Ip", value: "2001:db8::1",
			matches: []string{"2001:0db8:0:0:0:0:0:1"},
			misses:  []string{"2001:db8::2", "192.0.2.10", "::ffff:192.0.2.10"},
		},
		{
			name: "native IPv6 range", scope: "Range", value: "2001:db8::1/32",
			matches: []string{"2001:db8::", "2001:db8:ffff::1"},
			misses:  []string{"2001:db9::1", "192.0.2.10", "::ffff:192.0.2.10"},
		},
		{
			name: "native IPv6 default route", scope: "Range", value: "::/0",
			matches: []string{"::1", "2001:db8::1"},
			misses:  []string{"192.0.2.10", "::ffff:192.0.2.10"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision := testDecision(1, test.scope, test.value, "ban")
			key := keyForDecision(decision)
			s := newStore()
			require.NoError(t, s.add(decision))

			for _, queries := range []struct {
				addresses []string
				match     bool
			}{{test.matches, true}, {test.misses, false}} {
				for _, address := range queries.addresses {
					t.Run(address, func(t *testing.T) {
						ip := netip.MustParseAddr(address)
						stream, err := s.get(ip)
						require.NoError(t, err)
						live, err := selectDecision(ip, []*models.Decision{decision})
						require.NoError(t, err)
						if queries.match {
							requireDecisionIdentity(t, decision, stream)
							requireDecisionIdentity(t, decision, live)
						} else {
							require.Nil(t, stream)
							require.Nil(t, live)
						}
						require.Equal(t, key, keyForDecision(decision), "lookups must preserve the wire identity")
					})
				}
			}
		})
	}
}

func TestMappedAddressGroupsKeepIndependentTombstones(t *testing.T) {
	now := time.Date(2026, time.October, 13, 0, 0, 0, 0, time.UTC)
	s := newStoreWithClock(func() time.Time { return now })
	plain := testDecision(1, "Ip", "192.0.2.10", "ban")
	mapped := testDecision(2, "Ip", "::ffff:192.0.2.10", "ban")
	mappedRange := testDecision(3, "Range", "::ffff:192.0.2.10/128", "ban")
	for _, decision := range []*models.Decision{plain, mapped, mappedRange} {
		require.NoError(t, s.add(decision))
	}
	require.Equal(t, 3, s.store.Len())
	for _, decision := range s.activeDecisionSnapshot() {
		require.False(t, decision.IPv6, "mapped targets represent IPv4 decisions")
	}

	for _, ip := range []string{"192.0.2.10", "::ffff:192.0.2.10"} {
		stream, err := s.get(netip.MustParseAddr(ip))
		require.NoError(t, err)
		requireDecisionIdentity(t, plain, stream, "equivalent prefixes must have equal specificity")
		live, err := selectDecision(netip.MustParseAddr(ip), []*models.Decision{mappedRange, mapped, plain})
		require.NoError(t, err)
		requireDecisionIdentity(t, plain, live)
	}

	require.NoError(t, s.delete(testDecision(999, "Ip", *mapped.Value, "ban")))
	require.Equal(t, 2, s.store.Len(), "a semantic tombstone must remove only its exact wire group")
	require.NoError(t, s.delete(&models.Decision{ID: plain.ID}))
	require.Equal(t, 1, s.store.Len())
	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	requireDecisionIdentity(t, mappedRange, selected)
	require.NoError(t, s.delete(testDecision(999, "Range", *mappedRange.Value, "ban")))
	require.Zero(t, s.store.Len())
}
