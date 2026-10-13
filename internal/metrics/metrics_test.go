package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestRecalculateAndRecordDecisionCounts(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions"}, []string{
		labelOrigin, labelIPType,
	})

	counts := recalculateAndRecordDecisionCounts([]ActiveDecision{
		{Origin: "cscli"},
		{Origin: "cscli"},
		{Origin: "CAPI", IPv6: true},
	}, gauge, nil)

	assert.Equal(t, float64(2), gaugeValue(t, gauge.WithLabelValues("cscli", "ipv4")))
	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("CAPI", "ipv6")))
	assert.Equal(t, float64(0), gaugeValue(t, gauge.WithLabelValues("appsec", "ipv4")))

	recalculateAndRecordDecisionCounts([]ActiveDecision{{Origin: "cscli"}}, gauge, counts)

	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("cscli", "ipv4")))
	assert.Equal(t, float64(0), gaugeValue(t, gauge.WithLabelValues("CAPI", "ipv6")))
}

func TestRecalculateAndRecordDecisionCountsHandlesMissingMetadata(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions_missing_metadata"}, []string{
		labelOrigin, labelIPType,
	})

	assert.NotPanics(t, func() {
		recalculateAndRecordDecisionCounts([]ActiveDecision{{}}, gauge, nil)
	})
	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("unknown", "ipv4")))
}

func TestRecalculateAndRecordDecisionCountsRemovesStaleCustomOrigin(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions_custom_origin"}, []string{
		labelOrigin, labelIPType,
	})
	registry := prometheus.NewRegistry()
	registry.MustRegister(gauge)

	counts := recalculateAndRecordDecisionCounts([]ActiveDecision{{Origin: "custom"}}, gauge, nil)
	assert.True(t, hasGaugeSeries(t, registry, "custom", "ipv4"))

	recalculateAndRecordDecisionCounts(nil, gauge, counts)
	assert.False(t, hasGaugeSeries(t, registry, "custom", "ipv4"))
}

func TestDecisionCountsRemoveOnlyInactiveSeries(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions_retirement"}, []string{
		labelOrigin, labelIPType,
	})
	registry := prometheus.NewRegistry()
	registry.MustRegister(gauge)

	counts := recalculateAndRecordDecisionCounts([]ActiveDecision{
		{Origin: "custom"},
		{Origin: "custom", IPv6: true},
		{Origin: " "},
		{Origin: "cscli"},
	}, gauge, nil)
	activeGauge := gauge.WithLabelValues("custom", "ipv6")

	counts = recalculateAndRecordDecisionCounts([]ActiveDecision{
		{Origin: "custom", IPv6: true},
		{Origin: " custom ", IPv6: true},
		{Origin: "cscli", IPv6: true},
	}, gauge, counts)

	assert.Equal(t, float64(2), gaugeValue(t, activeGauge), "active gauges must remain attached to their series")
	assert.False(t, hasGaugeSeries(t, registry, "custom", "ipv4"))
	assert.False(t, hasGaugeSeries(t, registry, "unknown", "ipv4"))
	assert.Equal(t, float64(0), gaugeValue(t, gauge.WithLabelValues("cscli", "ipv4")))
	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("cscli", "ipv6")))

	recalculateAndRecordDecisionCounts(nil, gauge, counts)
	assert.False(t, hasGaugeSeries(t, registry, "custom", "ipv6"))
	families, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)
	assert.Len(t, families[0].GetMetric(), 14, "empty snapshots must retain only the default zero series")
}

func TestDecisionCountsStayVisibleDuringConcurrentCollection(t *testing.T) {
	usageRegistry := prometheus.NewRegistry()
	caddyRegistry := prometheus.NewRegistry()
	provider, err := NewProvider(nil, usageRegistry, caddyRegistry, time.Minute,
		zap.NewNop(), "testing", "v0.0.0", "test")
	require.NoError(t, err)

	const decisionCount = 100_000
	decisions := make([]ActiveDecision, decisionCount)
	for i := range decisions {
		if i%2 == 0 {
			decisions[i] = ActiveDecision{Origin: "cscli"}
		} else {
			decisions[i] = ActiveDecision{Origin: "custom", IPv6: true}
		}
	}
	provider.RecalculateAndRecordDecisionCounts(decisions)

	var publishers sync.WaitGroup
	for range 2 {
		publishers.Go(func() {
			for range 10 {
				provider.RecalculateAndRecordDecisionCounts(decisions)
			}
		})
	}
	done := make(chan struct{})
	go func() {
		publishers.Wait()
		close(done)
	}()
	t.Cleanup(func() { <-done })

	for {
		for _, registry := range []*prometheus.Registry{usageRegistry, caddyRegistry} {
			families, err := registry.Gather()
			require.NoError(t, err)
			seen := 0
			for _, family := range families {
				if family.GetName() != string(activeDecisionsName) {
					continue
				}
				for _, metric := range family.GetMetric() {
					origin := getLabelValue(metric.GetLabel(), labelOrigin)
					version := getLabelValue(metric.GetLabel(), labelIPType)
					if origin == "cscli" && version == "ipv4" || origin == "custom" && version == "ipv6" {
						require.EqualValues(t, decisionCount/2, metric.GetGauge().GetValue(),
							"unchanged decisions must not produce transient zero counts")
						seen++
					}
				}
			}
			require.Equal(t, 2, seen, "active series must remain visible during an update")
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func hasGaugeSeries(t *testing.T, registry *prometheus.Registry, origin, ipType string) bool {
	t.Helper()
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range metricFamilies {
		for _, metric := range family.GetMetric() {
			if getLabelValue(metric.GetLabel(), labelOrigin) == origin &&
				getLabelValue(metric.GetLabel(), labelIPType) == ipType {
				return true
			}
		}
	}
	return false
}

func gaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	metric := &model.Metric{}
	require.NoError(t, gauge.Write(metric))
	return metric.GetGauge().GetValue()
}
