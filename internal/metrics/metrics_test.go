package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecalculateAndRecordDecisionCounts(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions"}, []string{
		labelOrigin, labelIPType,
	})

	recalculateAndRecordDecisionCounts([]ActiveDecision{
		{Origin: "cscli"},
		{Origin: "cscli"},
		{Origin: "CAPI", IPv6: true},
	}, gauge)

	assert.Equal(t, float64(2), gaugeValue(t, gauge.WithLabelValues("cscli", "ipv4")))
	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("CAPI", "ipv6")))
	assert.Equal(t, float64(0), gaugeValue(t, gauge.WithLabelValues("appsec", "ipv4")))

	recalculateAndRecordDecisionCounts([]ActiveDecision{{Origin: "cscli"}}, gauge)

	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("cscli", "ipv4")))
	assert.Equal(t, float64(0), gaugeValue(t, gauge.WithLabelValues("CAPI", "ipv6")))
}

func TestRecalculateAndRecordDecisionCountsHandlesMissingMetadata(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions_missing_metadata"}, []string{
		labelOrigin, labelIPType,
	})

	assert.NotPanics(t, func() {
		recalculateAndRecordDecisionCounts([]ActiveDecision{{}}, gauge)
	})
	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("unknown", "ipv4")))
}

func TestRecalculateAndRecordDecisionCountsRemovesStaleCustomOrigin(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions_custom_origin"}, []string{
		labelOrigin, labelIPType,
	})
	registry := prometheus.NewRegistry()
	registry.MustRegister(gauge)

	recalculateAndRecordDecisionCounts([]ActiveDecision{{Origin: "custom"}}, gauge)
	assert.True(t, hasGaugeSeries(t, registry, "custom", "ipv4"))

	recalculateAndRecordDecisionCounts(nil, gauge)
	assert.False(t, hasGaugeSeries(t, registry, "custom", "ipv4"))
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
