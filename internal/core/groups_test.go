package core

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/require"
)

func TestStoreKeepsSameTargetRemediationsIndependent(t *testing.T) {
	for _, types := range [][]string{{"ban", "throttle"}, {"throttle", "ban"}} {
		t.Run(types[0]+" then "+types[1], func(t *testing.T) {
			s := newStore()
			for i, typ := range types {
				require.NoError(t, s.add(groupDecision(int64(i+1), "Ip", "192.0.2.10", typ)))
			}
			require.Equal(t, 2, (&Core{store: s}).NumberOfActiveDecisions())
			requireStoreType(t, s, "192.0.2.10", "ban")

			require.NoError(t, s.delete(groupDecision(999, "Ip", "192.0.2.10", "ban")))
			require.Equal(t, 1, s.Len())
			requireStoreType(t, s, "192.0.2.10", "throttle")
			require.NoError(t, s.delete(groupDecision(999, "Ip", "192.0.2.10", "throttle")))
			require.Zero(t, s.Len())
			selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
			require.NoError(t, err)
			require.Nil(t, selected)
		})
	}
}

func TestStoreExactWireGroupsShareAnIndexWithoutSharingTombstones(t *testing.T) {
	s := newStore()
	groups := []*models.Decision{
		groupDecision(1, "Ip", "192.0.2.10", "ban"),
		groupDecision(2, "Ip", "192.0.2.10/32", "ban"),
		groupDecision(3, "Range", "192.0.2.10/32", "ban"),
		groupDecision(4, "Range", "192.0.2.99/24", "captcha"),
		groupDecision(5, "Range", "192.0.2.0/24", "captcha"),
	}
	for _, decision := range groups {
		require.NoError(t, s.add(decision))
	}
	require.Equal(t, 5, s.Len())
	require.Len(t, s.activeDecisionSnapshot(), 5)

	for i, decision := range groups {
		// Complete tombstones identify the exact wire group, regardless of ID.
		tombstone := *decision
		tombstone.ID = 999
		require.NoError(t, s.delete(&tombstone))
		require.Equal(t, len(groups)-i-1, s.Len())
		if i < 2 {
			requireStoreType(t, s, "192.0.2.10", "ban")
		} else if i < 4 {
			requireStoreType(t, s, "192.0.2.10", "captcha")
		}
	}
	require.Empty(t, s.activeDecisionSnapshot())
}

func TestStoreSemanticUpsertAndIDOnlyDeletion(t *testing.T) {
	s := newStore()
	old := groupDecision(10, "Ip", "192.0.2.10", "ban")
	current := groupDecision(11, "Ip", "192.0.2.10", "ban")
	*current.Origin = "CAPI"
	throttle := groupDecision(12, "Ip", "192.0.2.10", "throttle")
	for _, decision := range []*models.Decision{old, current, throttle} {
		require.NoError(t, s.add(decision))
	}
	require.Equal(t, 2, s.Len(), "origin and ID do not create additional LAPI groups")

	require.NoError(t, s.delete(&models.Decision{ID: old.ID}))
	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	require.Same(t, current, selected, "superseded IDs must not remove the effective member")

	require.NoError(t, s.delete(&models.Decision{ID: current.ID}))
	require.Equal(t, 1, s.Len())
	requireStoreType(t, s, "192.0.2.10", "throttle")
	require.NoError(t, s.delete(&models.Decision{ID: throttle.ID}))
	require.Zero(t, s.Len())
	require.NoError(t, s.delete(throttle), "repeated deletion is harmless")
}

func TestStoreGroupTypeRemainsCaseSensitive(t *testing.T) {
	s := newStore()
	require.NoError(t, s.add(groupDecision(1, "Ip", "192.0.2.10", "ban")))
	require.NoError(t, s.add(groupDecision(2, "Ip", "192.0.2.10", "BAN")))
	require.Equal(t, 2, s.Len())
	require.NoError(t, s.delete(groupDecision(999, "Ip", "192.0.2.10", "ban")))
	require.Equal(t, 1, s.Len())
	requireStoreType(t, s, "192.0.2.10", "BAN")
}

func TestStoreIDUpdatesCanMoveBetweenTargets(t *testing.T) {
	s := newStore()
	require.NoError(t, s.add(groupDecision(1, "Ip", "192.0.2.10", "captcha")))
	updated := groupDecision(1, "Ip", "192.0.2.11", "ban")
	require.NoError(t, s.add(updated))
	require.Equal(t, 1, s.Len())
	old, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	require.Nil(t, old)
	selected, err := s.get(netip.MustParseAddr("192.0.2.11"))
	require.NoError(t, err)
	require.Same(t, updated, selected)
}

func TestStoreIDLessGroupReplacesItsEffectiveMember(t *testing.T) {
	s := newStore()
	first := groupDecision(0, "Ip", "192.0.2.10", "ban")
	second := groupDecision(0, "Ip", "192.0.2.10", "ban")
	*second.Origin = "CAPI"
	require.NoError(t, s.add(first))
	require.NoError(t, s.add(second))
	require.Equal(t, 1, s.Len())
	selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
	require.NoError(t, err)
	require.Same(t, second, selected)
	require.NoError(t, s.delete(groupDecision(0, "Ip", "192.0.2.10", "ban")))
	require.Zero(t, s.Len())
}

func TestStoreEqualPriorityGroupsKeepFirstSeenOrder(t *testing.T) {
	s := newStore()
	first := groupDecision(1, "Ip", "192.0.2.10", "ban")
	second := groupDecision(2, "Range", "192.0.2.10/32", "ban")
	*second.Origin = "CAPI"
	require.NoError(t, s.add(first))
	require.NoError(t, s.add(second))
	assertSelected := func(expected *models.Decision) {
		t.Helper()
		for range 100 {
			selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
			require.NoError(t, err)
			require.Same(t, expected, selected)
		}
	}
	assertSelected(first)

	updated := groupDecision(3, "Ip", "192.0.2.10", "ban")
	*updated.Origin = "console"
	require.NoError(t, s.add(updated))
	assertSelected(updated)
	require.NoError(t, s.delete(updated))
	assertSelected(second)
	require.NoError(t, s.add(updated))
	assertSelected(second)
}

func TestStoreGroupsKeepOverlappingPrefixesIndependent(t *testing.T) {
	s := newStore()
	rangeBan := groupDecision(1, "Range", "192.0.2.0/24", "ban")
	ipCaptcha := groupDecision(2, "Ip", "192.0.2.10", "captcha")
	require.NoError(t, s.add(rangeBan))
	require.NoError(t, s.add(ipCaptcha))
	require.Len(t, s.activeDecisionSnapshot(), 2, "overlap must not duplicate metric counts")
	requireStoreType(t, s, "192.0.2.10", "ban")
	require.NoError(t, s.delete(rangeBan))
	requireStoreType(t, s, "192.0.2.10", "captcha")
	require.Len(t, s.activeDecisionSnapshot(), 1)
}

func TestStoreSnapshotCopiesEveryGroupsLabels(t *testing.T) {
	s := newStore()
	ban := groupDecision(1, "Ip", "192.0.2.10", "ban")
	missingOrigin := groupDecision(2, "Ip", "192.0.2.10", "captcha")
	missingOrigin.Origin = nil
	for _, decision := range []*models.Decision{ban, missingOrigin, groupDecision(3, "Range", "2001::/16", "ban")} {
		require.NoError(t, s.add(decision))
	}
	snapshot := s.activeDecisionSnapshot()
	require.Len(t, snapshot, 3)
	ipv6 := 0
	for _, decision := range snapshot {
		if decision.IPv6 {
			ipv6++
		}
	}
	require.Equal(t, 1, ipv6, "address family is independent of prefix length")
	require.Nil(t, missingOrigin.Origin)
	require.NoError(t, s.delete(ban))
	*ban.Origin = "changed after snapshot"
	require.Len(t, snapshot, 3)
	for _, decision := range snapshot {
		require.NotEqual(t, "changed after snapshot", decision.Origin)
	}
}

func TestStoreGroupsConcurrentLookupAndUpdates(t *testing.T) {
	s := newStore()
	require.NoError(t, s.add(groupDecision(1, "Ip", "192.0.2.10", "captcha")))
	const readers = 8
	errs := make(chan error, readers+1)
	var wg sync.WaitGroup
	for range readers {
		wg.Go(func() {
			for range 100 {
				selected, err := s.get(netip.MustParseAddr("192.0.2.10"))
				if err != nil {
					errs <- err
					return
				}
				if selected == nil {
					errs <- fmt.Errorf("permanent captcha disappeared during a sibling update")
					return
				}
				_ = s.Len()
				_ = s.activeDecisionSnapshot()
			}
		})
	}
	wg.Go(func() {
		ban := groupDecision(2, "Ip", "192.0.2.10", "ban")
		for range 100 {
			if err := s.add(ban); err != nil {
				errs <- err
				return
			}
			if err := s.delete(ban); err != nil {
				errs <- err
				return
			}
		}
	})
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Equal(t, 1, s.Len())
	requireStoreType(t, s, "192.0.2.10", "captcha")
}

func groupDecision(id int64, scope, value, typ string) *models.Decision {
	duration, origin := "1h", "cscli"
	return &models.Decision{ID: id, Scope: &scope, Value: &value, Type: &typ, Duration: &duration, Origin: &origin}
}

func requireStoreType(t *testing.T, s *store, ip, typ string) {
	t.Helper()
	selected, err := s.get(netip.MustParseAddr(ip))
	require.NoError(t, err)
	require.NotNil(t, selected)
	require.Equal(t, typ, *selected.Type)
}
