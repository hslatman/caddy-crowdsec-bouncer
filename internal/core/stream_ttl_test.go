package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

func ttlTestCore(t *testing.T, apiURL string, registry *prometheus.Registry) *Core {
	t.Helper()
	metricsInterval := time.Duration(0)
	if registry != nil {
		// The provider records decision gauges only when metrics are enabled.
		metricsInterval = 15 * time.Minute
	}
	b, err := New("fixture-api-key", apiURL, true, "", 0, time.Second, false,
		50*time.Millisecond, false, zaptest.NewLogger(t), registry, metricsInterval)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Shutdown()) })
	return b
}

func ttlRequireActiveDecisionCount(t *testing.T, registry *prometheus.Registry, wanted float64) {
	t.Helper()
	require.Eventually(t, func() bool {
		families, err := registry.Gather()
		if err != nil {
			return false
		}
		for _, family := range families {
			if family.GetName() != "crowdsec_decisions_active" {
				continue
			}
			var count float64
			for _, metric := range family.GetMetric() {
				count += metric.GetGauge().GetValue()
			}
			return count == wanted
		}
		return false
	}, 3*time.Second, 10*time.Millisecond, "active-decision gauge must be populated before expiry")
}

func TestStreamCacheMaintenanceExpiresDuringLAPIOutage(t *testing.T) {
	var outage atomic.Bool
	var failedRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if outage.Load() {
			failedRequests.Add(1)
			http.Error(w, "fixture outage", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&models.DecisionsStreamResponse{
			New:     []*models.Decision{ttlDecision(1, "Ip", "192.0.2.1", "1h")},
			Deleted: []*models.Decision{},
		})
	}))
	defer server.Close()
	registry := prometheus.NewRegistry()
	b := ttlTestCore(t, server.URL+"/", registry)
	var clock atomic.Int64
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	clock.Store(start.UnixNano())
	b.store.now = func() time.Time { return time.Unix(0, clock.Load()) }
	b.Run(t.Context())
	require.Eventually(t, func() bool { return b.NumberOfActiveDecisions() == 1 }, 3*time.Second, 10*time.Millisecond)
	ttlRequireActiveDecisionCount(t, registry, 1)
	outage.Store(true)
	require.Eventually(t, func() bool { return failedRequests.Load() > 0 }, 3*time.Second, 10*time.Millisecond)
	clock.Store(start.Add(time.Hour).UnixNano())

	// Inspect raw storage without calling a pruning lookup/count. The existing
	// processor must reclaim expired entries even when LAPI never sends Deleted.
	require.Eventually(t, func() bool {
		b.store.mu.Lock()
		defer b.store.mu.Unlock()
		return len(b.store.entries) == 0 && b.store.store.Len() == 0
	}, 3*time.Second, 10*time.Millisecond)
	allowed, decision, err := b.IsAllowed(t.Context(), netip.MustParseAddr("192.0.2.1"), false, "")
	require.NoError(t, err)
	require.True(t, allowed)
	require.Nil(t, decision)

	families, err := registry.Gather()
	require.NoError(t, err)
	found := false
	for _, family := range families {
		if family.GetName() != "crowdsec_decisions_active" {
			continue
		}
		found = true
		for _, metric := range family.GetMetric() {
			require.Zero(t, metric.GetGauge().GetValue())
		}
	}
	require.True(t, found, "active-decision gauge must reflect maintenance expiry")
}

func TestStreamCacheLookupExpiryRefreshesMetricsWithoutLAPI(t *testing.T) {
	registry := prometheus.NewRegistry()
	b := ttlTestCore(t, "http://127.0.0.1:1/", registry)
	var clock atomic.Int64
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	clock.Store(start.UnixNano())
	b.store.now = func() time.Time { return time.Unix(0, clock.Load()) }
	require.NoError(t, b.store.add(ttlDecision(1, "Ip", "192.0.2.1", "1h")))
	b.store.recordDecisionCounts(b.metricsProvider)
	ttlRequireActiveDecisionCount(t, registry, 1)
	clock.Store(start.Add(time.Hour).UnixNano())
	got, err := b.store.get(netip.MustParseAddr("192.0.2.1"))
	require.NoError(t, err)
	require.Nil(t, got)

	ctx := t.Context()
	b.wg = &sync.WaitGroup{}
	b.startProcessingDecisions(ctx)
	defer b.wg.Wait()
	// Close the stream after the assertion so its receiver and ticker stop.
	defer close(b.streamingBouncer.Stream)
	require.Eventually(t, func() bool {
		families, err := registry.Gather()
		if err != nil {
			return false
		}
		for _, family := range families {
			if family.GetName() != "crowdsec_decisions_active" {
				continue
			}
			for _, metric := range family.GetMetric() {
				if metric.GetGauge().GetValue() != 0 {
					return false
				}
			}
			return true
		}
		return false
	}, 3*time.Second, 10*time.Millisecond)
}

func TestStreamCacheStartupWithoutLAPIRemainsFailOpen(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "fixture outage", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	b := ttlTestCore(t, server.URL+"/", nil)
	b.Run(t.Context())
	require.Eventually(t, func() bool { return requests.Load() > 0 }, 3*time.Second, 10*time.Millisecond)
	allowed, decision, err := b.IsAllowed(t.Context(), netip.MustParseAddr("192.0.2.1"), false, "")
	require.NoError(t, err)
	require.True(t, allowed)
	require.Nil(t, decision)
	require.Zero(t, b.NumberOfActiveDecisions())
}

func TestStreamCacheProcessorStopsWhenStreamCloses(t *testing.T) {
	b := ttlTestCore(t, "http://127.0.0.1:1/", nil)
	b.wg = &sync.WaitGroup{}
	b.startProcessingDecisions(t.Context())
	close(b.streamingBouncer.Stream)
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed stream must stop the existing processor")
	}
}

func TestStreamCacheInvalidBatchIsRejectedWithoutProcessorPanic(t *testing.T) {
	b := ttlTestCore(t, "http://127.0.0.1:1/", nil)
	b.wg = &sync.WaitGroup{}
	b.startProcessingDecisions(t.Context())
	defer b.wg.Wait()
	defer close(b.streamingBouncer.Stream)
	missingTTL := ttlDecision(2, "Ip", "192.0.2.2", "1m")
	missingTTL.Duration = nil
	missingValue := ttlDecision(3, "Ip", "192.0.2.3", "1m")
	missingValue.Value = nil
	b.streamingBouncer.Stream <- &models.DecisionsStreamResponse{
		New:     []*models.Decision{nil, missingTTL, missingValue},
		Deleted: []*models.Decision{nil, {ID: 0}},
	}
	// A second batch proves that the processor survived all malformed models.
	b.streamingBouncer.Stream <- &models.DecisionsStreamResponse{
		New: []*models.Decision{ttlDecision(4, "Ip", "192.0.2.4", "1m")},
	}
	require.Eventually(t, func() bool { return b.NumberOfActiveDecisions() == 1 }, time.Second, time.Millisecond)
}
