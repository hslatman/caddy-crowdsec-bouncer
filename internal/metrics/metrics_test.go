// Copyright 2026 Herman Slatman
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

package metrics

import (
	"net/netip"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/hslatman/ipstore"
	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecalculateAndRecordDecisionCounts(t *testing.T) {
	store := ipstore.New[*models.Decision]()
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions"}, []string{
		labelOrigin, labelIPType,
	})

	require.NoError(t, store.Add(netip.MustParseAddr("192.0.2.1"), metricDecision("cscli", "ban")))
	require.NoError(t, store.Add(netip.MustParseAddr("192.0.2.2"), metricDecision("cscli", "captcha")))
	require.NoError(t, store.Add(netip.MustParseAddr("2001:db8::1"), metricDecision("CAPI", "CAPTCHA")))

	recalculateAndRecordDecisionCounts(store, gauge)

	assert.Equal(t, float64(2), gaugeValue(t, gauge.WithLabelValues("cscli", "ipv4")))
	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("CAPI", "ipv6")))
	assert.Equal(t, float64(0), gaugeValue(t, gauge.WithLabelValues("appsec", "ipv4")))

	_, err := store.Remove(netip.MustParseAddr("192.0.2.2"))
	require.NoError(t, err)
	recalculateAndRecordDecisionCounts(store, gauge)

	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("cscli", "ipv4")))
}

func TestRecalculateAndRecordDecisionCountsHandlesMissingMetadata(t *testing.T) {
	store := ipstore.New[*models.Decision]()
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_active_decisions_missing_metadata"}, []string{
		labelOrigin, labelIPType,
	})
	require.NoError(t, store.Add(netip.MustParseAddr("192.0.2.1"), &models.Decision{}))

	assert.NotPanics(t, func() {
		recalculateAndRecordDecisionCounts(store, gauge)
	})
	assert.Equal(t, float64(1), gaugeValue(t, gauge.WithLabelValues("unknown", "ipv4")))
}

func metricDecision(origin, remediation string) *models.Decision {
	return &models.Decision{Origin: &origin, Type: &remediation}
}

func gaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	metric := &model.Metric{}
	require.NoError(t, gauge.Write(metric))
	return metric.GetGauge().GetValue()
}
