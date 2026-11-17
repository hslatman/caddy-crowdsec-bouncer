package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestDecisionCountsFromGroupSnapshot(t *testing.T) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_decision_groups"}, []string{labelOrigin, labelIPType})
	recalculateAndRecordDecisionCounts([]ActiveDecision{
		{Origin: "cscli"}, {Origin: "cscli"}, {Origin: "CAPI", IPv6: true}, {},
	}, gauge)
	requireGaugeValue(t, gauge, "cscli", "ipv4", 2)
	requireGaugeValue(t, gauge, "CAPI", "ipv6", 1)
	requireGaugeValue(t, gauge, "", "ipv4", 1)

	recalculateAndRecordDecisionCounts([]ActiveDecision{{Origin: "cscli"}}, gauge)
	requireGaugeValue(t, gauge, "cscli", "ipv4", 1)
	requireGaugeValue(t, gauge, "CAPI", "ipv6", 0)
}

func requireGaugeValue(t *testing.T, gauge *prometheus.GaugeVec, origin, ipType string, value float64) {
	t.Helper()
	metric := &model.Metric{}
	require.NoError(t, gauge.WithLabelValues(origin, ipType).Write(metric))
	require.Equal(t, value, metric.GetGauge().GetValue())
}
