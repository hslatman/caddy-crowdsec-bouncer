package core

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/stretchr/testify/require"
)

func ttlDecision(id int64, scope, value, ttl string) *models.Decision {
	typ, origin := "ban", "cscli"
	return &models.Decision{
		ID: id, Scope: &scope, Value: &value, Duration: &ttl,
		Type: &typ, Origin: &origin,
	}
}

func TestStreamCacheExactExpiryWithoutDeleted(t *testing.T) {
	for _, tc := range []struct {
		name, scope, value, ip string
	}{
		{"ipv4", "Ip", "192.0.2.1", "192.0.2.1"},
		{"ipv4-host-prefix", "Ip", "192.0.2.1/32", "192.0.2.1"},
		{"ipv6", "Ip", "2001:db8::1", "2001:db8::1"},
		{"ipv6-host-prefix", "Ip", "2001:db8::1/128", "2001:db8::1"},
		{"ipv4-range", "Range", "192.0.2.77/24", "192.0.2.42"},
		{"ipv6-range", "Range", "2001:db8::1/64", "2001:db8::42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore()
			now := time.Now()
			s.now = func() time.Time { return now }
			d := ttlDecision(1, tc.scope, tc.value, "10m")
			require.NoError(t, s.add(d))
			ip := netip.MustParseAddr(tc.ip)
			now = now.Add(10*time.Minute - time.Nanosecond)
			got, err := s.get(ip)
			require.NoError(t, err)
			require.NotNil(t, got)
			now = now.Add(time.Nanosecond)
			got, err = s.get(ip)
			require.NoError(t, err)
			require.Nil(t, got, "no LAPI Deleted message is required at expiry")
			require.Zero(t, s.len())
			require.Zero(t, s.store.Len())
		})
	}
}

func TestStreamCacheInvalidDecisionNeverCreatesBan(t *testing.T) {
	for _, ttl := range []string{"", "0", "0s", "-1s", "nonsense", "999999999999999999h"} {
		t.Run("ttl-"+ttl, func(t *testing.T) {
			s := newStore()
			err := s.add(ttlDecision(1, "Ip", "192.0.2.23", ttl))
			require.Error(t, err)
			require.NotContains(t, err.Error(), "192.0.2.23")
			require.Zero(t, s.len())
		})
	}
	for _, field := range []string{"decision", "scope", "value", "type", "origin", "duration", "id"} {
		t.Run("missing-"+field, func(t *testing.T) {
			s := newStore()
			d := ttlDecision(1, "Ip", "192.0.2.23", "10m")
			switch field {
			case "decision":
				d = nil
			case "scope":
				d.Scope = nil
			case "value":
				d.Value = nil
			case "type":
				d.Type = nil
			case "origin":
				d.Origin = nil
			case "duration":
				d.Duration = nil
			case "id":
				d.ID = 0
			}
			require.Error(t, s.add(d))
			require.Zero(t, s.len())
		})
	}
	for _, tc := range []struct{ scope, value string }{
		{"Ip", "192.0.2.0/24"}, {"Range", "not-a-range"}, {"Unknown", "192.0.2.23"},
	} {
		s := newStore()
		err := s.add(ttlDecision(1, tc.scope, tc.value, "10m"))
		require.Error(t, err)
		require.NotContains(t, err.Error(), tc.value)
		require.Zero(t, s.len())
	}
}

func TestStreamCacheDuplicateDoesNotExtendAndInvalidUpdateDoesNotRenew(t *testing.T) {
	s := newStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	ip := netip.MustParseAddr("192.0.2.1")
	require.NoError(t, s.add(ttlDecision(1, "Ip", ip.String(), "10m")))
	now = now.Add(9 * time.Minute)
	require.NoError(t, s.add(ttlDecision(1, "Ip", ip.String()+"/32", "10m")))
	require.Equal(t, 1, s.len(), "IP and host prefix have one canonical key")
	require.Error(t, s.add(ttlDecision(2, "Ip", ip.String(), "bad-ttl")))
	now = now.Add(time.Minute)
	got, err := s.get(ip)
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestStreamCacheDuplicateMayShortenDeadline(t *testing.T) {
	s := newStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	ip := netip.MustParseAddr("192.0.2.1")
	require.NoError(t, s.add(ttlDecision(1, "Ip", ip.String(), "10m")))
	now = now.Add(time.Minute)
	require.NoError(t, s.add(ttlDecision(1, "Ip", ip.String(), "1m")))
	now = now.Add(time.Minute)
	got, err := s.get(ip)
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestStreamCacheExpiredMatchDoesNotMaskActiveMatch(t *testing.T) {
	for _, specificTTL := range []string{"1s", "10m"} {
		t.Run(specificTTL, func(t *testing.T) {
			s := newStore()
			now := time.Now()
			s.now = func() time.Time { return now }
			rangeTTL := "10m"
			wantID := int64(2)
			if specificTTL == "10m" {
				rangeTTL, wantID = "1s", 1
			}
			require.NoError(t, s.add(ttlDecision(1, "Ip", "192.0.2.1", specificTTL)))
			require.NoError(t, s.add(ttlDecision(2, "Range", "192.0.2.77/24", rangeTTL)))
			now = now.Add(time.Second)
			got, err := s.get(netip.MustParseAddr("192.0.2.1"))
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, wantID, got.ID)
			require.Equal(t, 1, s.len())
		})
	}
}

func TestStreamCacheStaleDeleteDoesNotRemoveReplacement(t *testing.T) {
	s := newStore()
	old := ttlDecision(1, "Ip", "192.0.2.1", "1m")
	replacement := ttlDecision(2, "Ip", "192.0.2.1/32", "2m")
	require.NoError(t, s.add(old))
	require.NoError(t, s.add(replacement))
	require.NoError(t, s.delete(old))
	got, err := s.get(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	require.Equal(t, int64(2), got.ID)
	require.NoError(t, s.delete(replacement))
	require.Zero(t, s.len())
}

func TestStreamCacheSnapshotsRequiredModelFields(t *testing.T) {
	s := newStore()
	d := ttlDecision(1, "Ip", "192.0.2.1", "10m")
	require.NoError(t, s.add(d))
	*d.Value, *d.Duration, *d.Origin, *d.Type = "198.51.100.1", "0s", "changed", "changed"
	got, err := s.get(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1", *got.Value)
	require.Equal(t, "10m", *got.Duration)
	require.Equal(t, "cscli", *got.Origin)
	require.Equal(t, "ban", *got.Type)
}

func TestStreamCacheConcurrentLookupUpdateExpiryAndMetrics(t *testing.T) {
	b, err := newCore(t)
	require.NoError(t, err)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Go(func() {
			for i := 0; i < 200; i++ {
				value := fmt.Sprintf("10.0.%d.%d", worker, i)
				d := ttlDecision(int64(worker*200+i+1), "Ip", value, "1ms")
				if err := b.store.add(d); err != nil {
					t.Error(err)
					return
				}
				if _, err := b.store.get(netip.MustParseAddr(value)); err != nil {
					t.Error(err)
					return
				}
				if i%3 == 0 {
					b.store.expire()
				}
				if i%5 == 0 {
					b.store.recordDecisionCounts(b.metricsProvider)
				}
				if err := b.store.delete(d); err != nil {
					t.Error(err)
					return
				}
				_ = b.NumberOfActiveDecisions()
			}
		})
	}
	wg.Wait()
	require.Zero(t, b.store.len())
}

func TestStreamCacheRejectMessagesDoNotContainAddressOrTTL(t *testing.T) {
	s := newStore()
	d := ttlDecision(1, "Ip", "192.0.2.123", "secret-marker-invalid-ttl")
	err := s.add(d)
	require.Error(t, err)
	for _, sensitive := range []string{*d.Value, *d.Duration} {
		require.False(t, strings.Contains(err.Error(), sensitive))
	}
}

func TestStreamCacheExpiryPreservesStrictestLiveRemediation(t *testing.T) {
	s := newStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	ip := netip.MustParseAddr("192.0.2.1")
	captcha := ttlDecision(1, "Ip", ip.String(), "10m")
	*captcha.Type = "captcha"
	ban := ttlDecision(2, "Range", "192.0.2.0/24", "1m")
	require.NoError(t, s.add(captcha))
	require.NoError(t, s.add(ban))
	got, err := s.get(ip)
	require.NoError(t, err)
	require.Equal(t, int64(2), got.ID)
	now = now.Add(time.Minute)
	got, err = s.get(ip)
	require.NoError(t, err)
	require.Equal(t, int64(1), got.ID)
	require.Equal(t, "captcha", *got.Type)
}
