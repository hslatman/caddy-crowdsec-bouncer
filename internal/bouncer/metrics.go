package bouncer

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/version"
	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

func init() {
	csbouncer.TotalLAPICalls = prometheus.NewCounter(prometheus.CounterOpts{
		Name: string(totalBouncerCallsName),
		Help: "The total number of calls to CrowdSec LAPI",
	})
	csbouncer.TotalLAPIError = prometheus.NewCounter(prometheus.CounterOpts{
		Name: string(totalBouncerErrorsName),
		Help: "The total number of failed calls to CrowdSec LAPI",
	})

	totalBouncerCallsCounter = csbouncer.TotalLAPICalls
	totalBouncerErrorsCounter = csbouncer.TotalLAPIError
}

var (
	// metrics provided by the go-cs-bouncer package; overridden in init to have more consistent name
	totalBouncerCallsCounter  prometheus.Counter
	totalBouncerErrorsCounter prometheus.Counter

	// appsec metrics; not provided by the go-cs-bouncer package
	totalAppSecCallsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: string(totalAppSecCallsName),
		Help: "The total number of calls to the CrowdSec LAPI AppSec component",
	})
	totalAppSecErrorsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: string(totalAppSecErrorsName),
		Help: "The total number of failed calls to the CrowdSec LAPI AppSec component",
	})

	// decision metrics; not provided by the go-cs-bouncer package
	activeDecisionsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: string(activeDecisionsName),
		Help: "The current number of active decisions",
	}, []string{"origin", "ip_type"})
	blockedRequestsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(blockedRequestsCounterName),
		Help: "The total number of requests blocked",
	}, []string{"server", "origin", "remediation", "ip_type"})
	processedRequestsCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(processedRequestsCounterName),
		Help: "The total number of requests handled",
	}, []string{"server", "ip_type"})

	// TODO: referencing the global metrics from csbouncer may not be the right
	// thing to do with how the CrowdSec module operates as part of Caddy. On
	// configuration reloads it would be pointing to the same counters. Thay may,
	// or may not be what we want. To be tested.
)

type metricName string

var (
	activeDecisionsName          metricName = "crowdsec_decisions_active"
	blockedRequestsCounterName   metricName = "crowdsec_requests_blocked"
	processedRequestsCounterName metricName = "crowdsec_requests_processed"
	totalBouncerCallsName        metricName = "crowdsec_bouncer_lapi_requests_total"
	totalBouncerErrorsName       metricName = "crowdsec_bouncer_lapi_requests_failures_total"
	totalAppSecCallsName         metricName = "crowdsec_appsec_lapi_requests_total"
	totalAppSecErrorsName        metricName = "crowdsec_appsec_lapi_requests_failures_total"
)

type metricConfig struct {
	Name         string
	Unit         string
	Collector    prometheus.Collector
	LabelKeys    []string
	LastValueMap map[string]float64 // keeps value that was sent last, and used to calculate the delta
	KeyFunc      func(labels []*model.LabelPair) string
	SendToLAPI   bool
}

type metricMap map[metricName]*metricConfig

func (m metricMap) RegisterAll(registry *prometheus.Registry) error {
	if registry == nil {
		return nil
	}

	for _, metric := range m {
		if err := registry.Register(metric.Collector); err != nil {
			return err
		}
	}

	return nil
}

func newMetricsProvider(client *apiclient.ApiClient, metricsRegistry, caddyMetricsRegistry *prometheus.Registry, interval time.Duration, logger *zap.Logger, instanceID string) (*metricsProvider, error) {
	metricMap := &metricMap{
		activeDecisionsName: {
			Name:         "active_decisions",
			Unit:         "ip",
			Collector:    activeDecisionsGauge,
			LabelKeys:    []string{"origin", "ip_type"},
			LastValueMap: nil, // absolute value
			KeyFunc: func(labels []*model.LabelPair) string {
				return getLabelValue(labels, "origin") + getLabelValue(labels, "ip_type")
			},
			SendToLAPI: true,
		},
		blockedRequestsCounterName: {
			Name:         "dropped",
			Unit:         "request",
			Collector:    blockedRequestsCounter,
			LabelKeys:    []string{"server", "origin", "remediation", "ip_type"},
			LastValueMap: make(map[string]float64),
			KeyFunc: func(labels []*model.LabelPair) string {
				return getLabelValue(labels, "server") + getLabelValue(labels, "origin") + getLabelValue(labels, "remediation") + getLabelValue(labels, "ip_type")
			},
			SendToLAPI: true,
		},
		processedRequestsCounterName: {
			Name:         "processed",
			Unit:         "request",
			Collector:    processedRequestsCounter,
			LabelKeys:    []string{"server", "ip_type"},
			LastValueMap: make(map[string]float64),
			KeyFunc: func(labels []*model.LabelPair) string {
				return getLabelValue(labels, "server") + getLabelValue(labels, "ip_type")
			},
			SendToLAPI: true,
		},
		totalBouncerCallsName: {
			Name:         "bouncer_calls",
			Unit:         "request",
			Collector:    totalBouncerCallsCounter,
			LabelKeys:    []string{},
			LastValueMap: make(map[string]float64),
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
		totalBouncerErrorsName: {
			Name:         "bouncer_errors",
			Unit:         "request",
			Collector:    totalBouncerErrorsCounter,
			LabelKeys:    []string{},
			LastValueMap: make(map[string]float64),
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
		totalAppSecCallsName: {
			Name:         "appsec_calls",
			Unit:         "request",
			Collector:    totalAppSecCallsCounter,
			LabelKeys:    []string{},
			LastValueMap: make(map[string]float64),
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
		totalAppSecErrorsName: {
			Name:         "appsec_errors",
			Unit:         "request",
			Collector:    totalAppSecErrorsCounter,
			LabelKeys:    []string{},
			LastValueMap: make(map[string]float64),
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
	}

	// register the metrics with the registry
	if err := metricMap.RegisterAll(metricsRegistry); err != nil {
		return nil, fmt.Errorf("failed registering metrics: %w", err)
	}

	// register the metrics with the Caddy metrics registry
	if err := metricMap.RegisterAll(caddyMetricsRegistry); err != nil {
		return nil, fmt.Errorf("failed registering metrics with Caddy registry: %w", err)
	}

	osName, osVersion := version.DetectOS()

	m := &metricsProvider{
		apiClient:            client,
		interval:             interval,
		metricMap:            metricMap,
		metricsRegistry:      metricsRegistry,
		caddyMetricsRegistry: caddyMetricsRegistry,
		bouncerType:          userAgentName,
		bouncerVersion:       userAgentVersion,
		bouncerOS: models.OSversion{
			Name:    &osName,
			Version: &osVersion,
		},
		bouncerFeatureFlags: []string{}, // not used in bouncers?
		logger:              logger.With(zap.String("instance_id", instanceID)),
		instanceID:          instanceID,
	}

	return m, nil
}

type metricsProvider struct {
	apiClient            *apiclient.ApiClient
	interval             time.Duration
	metricMap            *metricMap
	metricsRegistry      *prometheus.Registry
	caddyMetricsRegistry *prometheus.Registry
	logger               *zap.Logger
	bouncerType          string
	bouncerVersion       string
	bouncerOS            models.OSversion
	bouncerFeatureFlags  []string
	instanceID           string
	startedAtTimestamp   int64
	started              atomic.Bool
	initialMetricsSent   atomic.Bool
	lastMetricsSentAt    time.Time
	sending              sync.Mutex
}

func (m *metricsProvider) metricsPayload(now time.Time) (metrics *models.AllMetrics) {
	metrics = &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{
			{
				Name: userAgentName,
				Type: m.bouncerType,
				BaseMetrics: models.BaseMetrics{
					Os:                  &m.bouncerOS,
					Version:             &m.bouncerVersion,
					FeatureFlags:        m.bouncerFeatureFlags,
					UtcStartupTimestamp: &m.startedAtTimestamp,
				},
			},
		},
	}

	items, err := getMetricItems(m.metricsRegistry, m.metricMap)
	if err != nil {
		m.logger.Error("failed getting metrics", zap.Error(err))
		return
	}

	windowSizeSeconds := float64(0)
	if !m.lastMetricsSentAt.IsZero() {
		windowSizeSeconds = max(math.Abs(now.Sub(m.lastMetricsSentAt).Seconds()), windowSizeSeconds)
	}

	metrics.RemediationComponents[0].Metrics = []*models.DetailedMetrics{
		{
			Meta: &models.MetricsMeta{
				UtcNowTimestamp:   ptr.Of(now.Unix()),
				WindowSizeSeconds: ptr.Of(int64(windowSizeSeconds)),
			},
			Items: items,
		},
	}

	return metrics
}

func getLabelValue(labels []*model.LabelPair, key string) string {
	for _, label := range labels {
		if label.GetName() == key {
			return label.GetValue()
		}
	}

	return ""
}

func getMetricItems(registry *prometheus.Registry, metricMap *metricMap) ([]*models.MetricsDetailItem, error) {
	metricFamilies, err := registry.Gather()
	if err != nil {
		return nil, fmt.Errorf("failed gathering metrics: %w", err)
	}

	items := make([]*models.MetricsDetailItem, 0, len(metricFamilies))

	for _, mf := range metricFamilies {
		// filter out metrics for which no configuration is present
		cfg, ok := ptr.OrEmpty(metricMap)[metricName(mf.GetName())]
		if !ok {
			continue
		}

		// only include metrics explicitly enabled to be sent to CrowdSec Local API.
		if !cfg.SendToLAPI {
			continue
		}

		for _, metric := range mf.GetMetric() {
			var metricValue float64
			if counter := metric.GetCounter(); counter != nil {
				metricValue = counter.GetValue()
			} else if gauge := metric.GetGauge(); gauge != nil {
				metricValue = gauge.GetValue()
			} else {
				continue // no support for other metric types, currently
			}

			labels := metric.GetLabel()
			labelMap := make(map[string]string)
			for _, key := range cfg.LabelKeys {
				labelMap[key] = getLabelValue(labels, key)
			}

			var value float64
			if cfg.LastValueMap == nil {
				value = metricValue // absolute value
			} else {
				key := cfg.KeyFunc(labels)
				value = math.Abs(metricValue - cfg.LastValueMap[key]) // calculate delta for non-absolute values
				cfg.LastValueMap[key] = metricValue
			}

			items = append(items, &models.MetricsDetailItem{
				Name:   ptr.Of(cfg.Name),
				Value:  &value,
				Labels: labelMap,
				Unit:   ptr.Of(cfg.Unit),
			})
		}
	}

	return items, nil
}

var errMetricsProviderHalted = errors.New("metrics provider halted")

func (m *metricsProvider) run(ctx context.Context, startedAt time.Time) error {
	if m.started.Load() {
		return nil
	}

	if m.interval <= 0 {
		m.logger.Info("usage metrics disabled")
		return nil
	}

	if m.interval < 15*time.Minute {
		m.logger.Warn("low metrics push interval detected; CrowdSec suggest a minimum of 15 minutes", zap.Duration("interval", m.interval))
	}

	m.startedAtTimestamp = startedAt.Unix()
	m.started.Store(true)

	ticker := time.NewTicker(m.interval)

	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				m.logger.Error("metrics provider stopped", zap.Error(err))
				return nil
			}

			return errMetricsProviderHalted
		case <-ticker.C:
			_ = m.sendMetrics(ctx)
		}
	}
}

func (m *metricsProvider) sendMetrics(ctx context.Context) (sent bool) {
	if !m.started.Load() { // metrics disabled, or not started (yet)
		return
	}

	m.sending.Lock()
	defer m.sending.Unlock()

	now := time.Now()
	metrics := m.metricsPayload(now)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, resp, err := m.apiClient.UsageMetrics.Add(ctx, metrics)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		m.logger.Warn("timeout sending metrics")
		return
	case err != nil:
		m.logger.Warn("failed to send metrics", zap.Error(err))
		return
	case resp == nil || resp.Response == nil:
		m.logger.Warn("no response from metrics endpoint")
		return
	case resp.Response.StatusCode == http.StatusNotFound:
		m.logger.Warn("metrics endpoint not found; older LAPI?")
		return
	case resp.Response.StatusCode != http.StatusCreated:
		m.logger.Warn("failed to send metrics", zap.Int("status", resp.Response.StatusCode))
		return
	}

	sent = true
	m.lastMetricsSentAt = now

	isInitial := !m.initialMetricsSent.Load()
	if isInitial {
		m.initialMetricsSent.Store(sent)
	}

	m.logger.Debug("usage metrics sent", zap.Any("metrics", metrics), zap.Bool("initial", isInitial), zap.Time("next", now.Add(m.interval).Truncate(time.Second)))

	return
}

func (m *metricsProvider) sendInitialMetricsOnce(ctx context.Context) {
	if m.initialMetricsSent.Load() {
		return
	}

	_ = m.sendMetrics(ctx)
}

func (b *Bouncer) startMetricsProvider(ctx context.Context) {
	b.wg.Go(func() {
		b.logger.Debug("starting metrics provider", b.zapField())
		if err := b.metricsProvider.run(ctx, b.startedAt); err != nil {
			if errors.Is(err, errMetricsProviderHalted) {
				b.logger.Info("metrics provider stopped", b.zapField())
			} else {
				b.logger.Error("failed running metrics provider", b.zapField(), zap.Error(err))
			}
		}
	})
}
