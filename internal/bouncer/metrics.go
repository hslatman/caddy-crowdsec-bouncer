package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

var (
	// metrics provided by the go-cs-bouncer package
	totalLAPICallsCounter  = csbouncer.TotalLAPICalls
	totalLAPIErrorsCounter = csbouncer.TotalLAPIError

	// appsec metrics; not provided by the go-cs-bouncer package
	totalAppSecCallsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: string(totalAppSecCallsName),
		Help: "The total number of calls to CrowdSec LAPI AppSec component",
	})
	totalAppSecErrorsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: string(totalAppSecErrorsName),
		Help: "The total number of failed calls to CrowdSec LAPI AppSec component",
	})
	activeDecisionsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: string(activeDecisionsName),
		Help: "Denotes the current number of active decisions",
	}, []string{}) // TODO: additional labels, similar to firewall bouncer?
	blockedRequestsCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: string(blockedRequestsCounterName),
		Help: "The total number of requests blocked", // TODO: split between bouncer / appsec?
	})

	// TODO: additional metrics for number of blocked IPs / requests?
	// TODO: referencing the global metrics from csbouncer may not be the right
	// thing to do with how the CrowdSec module operates as part of Caddy. On
	// configuration reloads it would be pointing to the same counters. Thay may,
	// or may not be what we want.
)

type metricName string

var (
	activeDecisionsName        metricName = "caddy_bouncer_active_decisions"
	blockedRequestsCounterName metricName = "caddy_bouncer_blocked_requests"
	totalLAPICallsName         metricName = "lapi_requests_total"          // TODO: name not to be changed, unless counter overridden too
	totalLAPIErrorsName        metricName = "lapi_requests_failures_total" // TODO: name not to be changed, unless counter overridden too
	totalAppSecCallsName       metricName = "caddy_bouncer_lapi_appsec_requests_total"
	totalAppSecErrorsName      metricName = "caddy_bouncer_lapi_appsec_requests_failures_total"
)

type metricConfig struct {
	Name         string
	Unit         string
	Collector    prometheus.Collector
	LabelKeys    []string
	LastValueMap map[string]float64 // keep last value to send deltas -- nil if absolute
	KeyFunc      func(labels []*model.LabelPair) string
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
	osName, osVersion := version.DetectOS()
	metricMap := &metricMap{
		activeDecisionsName: {
			Name:         "active_decisions",
			Unit:         "ip",
			Collector:    activeDecisionsGauge,
			LabelKeys:    []string{},
			LastValueMap: nil, // TODO: should this be set?
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
		blockedRequestsCounterName: {
			Name:         "blocked_requests", // TODO: change name? Check other bouncers
			Unit:         "request",
			Collector:    blockedRequestsCounter,
			LabelKeys:    []string{},
			LastValueMap: make(map[string]float64),
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
		totalLAPICallsName: {
			Name:         "lapi_calls",
			Unit:         "integer",
			Collector:    totalLAPICallsCounter,
			LabelKeys:    []string{},
			LastValueMap: make(map[string]float64),
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
		totalLAPIErrorsName: {
			Name:         "lapi_errors",
			Unit:         "integer",
			Collector:    totalLAPIErrorsCounter,
			LabelKeys:    []string{},
			LastValueMap: make(map[string]float64),
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
		totalAppSecCallsName: {
			Name:         "appsec_calls",
			Unit:         "integer",
			Collector:    totalAppSecCallsCounter,
			LabelKeys:    []string{},
			LastValueMap: make(map[string]float64),
			KeyFunc:      func([]*model.LabelPair) string { return "" },
		},
		totalAppSecErrorsName: {
			Name:         "appsec_errors",
			Unit:         "integer",
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
		// TODO: only do this conditionally, when explicitly enabled?
		// TODO: register the metrics on this registry under different names?
		return nil, fmt.Errorf("failed registering metrics with Caddy registry: %w", err)
	}

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
		bouncerFeatureFlags: []string{}, // TODO: set this, but to what?
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
}

func (m *metricsProvider) metricsPayload() *models.AllMetrics {
	base := &models.BaseMetrics{
		Os:                  &m.bouncerOS,
		Version:             &m.bouncerVersion,
		FeatureFlags:        m.bouncerFeatureFlags,
		Metrics:             make([]*models.DetailedMetrics, 0),
		UtcStartupTimestamp: &m.startedAtTimestamp,
	}

	metric := &models.RemediationComponentsMetrics{
		BaseMetrics: *base,
		Type:        m.bouncerType,
	}

	m.updateMetrics(metric) // TODO: extract?

	return &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{metric},
	}
}

func getLabelValue(labels []*model.LabelPair, key string) string {
	for _, label := range labels {
		if label.GetName() == key {
			return label.GetValue()
		}
	}

	return ""
}

// TODO: refactor; this doesn't need to be a callback in the new implementation
func (m *metricsProvider) updateMetrics(metrics *models.RemediationComponentsMetrics) {
	//m.Name = userAgentName // instance ID? Is name provided when creating bouncer in CrowdSec, it seems
	//m.Version = ptr.Of(userAgentVersion)
	//m.Type = userAgentName

	// TODO: store/cache the previous metric value; only send the difference to LAPI?

	metricFamilies, err := m.metricsRegistry.Gather()
	if err != nil {
		m.logger.Error("failed gathering metrics", zap.Error(err))
		return
	}

	var items = make([]*models.MetricsDetailItem, 0, len(metricFamilies))

	for _, mf := range metricFamilies {
		cfg, ok := ptr.OrEmpty(m.metricMap)[metricName(mf.GetName())]
		if !ok {
			continue
		}

		for _, metric := range mf.GetMetric() {
			labels := metric.GetLabel()
			var value float64
			if counter := metric.GetCounter(); counter != nil {
				value = counter.GetValue()
			} else if gauge := metric.GetGauge(); gauge != nil {
				value = gauge.GetValue()
			} else {
				continue
			}

			labelMap := make(map[string]string)
			for _, key := range cfg.LabelKeys {
				labelMap[key] = getLabelValue(labels, key)
			}

			finalValue := value

			if cfg.LastValueMap == nil {
				// always send absolute values
				//log.Debugf("Sending %s for %+v %f", cfg.Name, labelMap, finalValue)
			} else {
				// the final value to send must be relative, and never negative
				// because the firewall counter may have been reset since last collection.
				key := cfg.KeyFunc(labels)

				// no need to guard access to LastValueMap, as we are in the main thread -- it's
				// the gauge that is updated by the requests
				finalValue = value - cfg.LastValueMap[key]

				if finalValue < 0 {
					finalValue = -finalValue

					//log.Warningf("metric value for %s %+v is negative, assuming external counter was reset", cfg.Name, labelMap)
				}

				cfg.LastValueMap[key] = value
				//log.Debugf("Sending %s for %+v %f | current value: %f | previous value: %f", cfg.Name, labelMap, finalValue, value, cfg.LastValueMap[key])
			}

			fmt.Println("appending item", mf.GetName(), value, finalValue)

			items = append(items, &models.MetricsDetailItem{ // TODO: add additional metrics
				Name:   ptr.Of(cfg.Name),
				Value:  &finalValue,
				Labels: labelMap,
				Unit:   ptr.Of(cfg.Unit),
			})
		}
	}

	fmt.Println(metricFamilies)

	// number := getMetricValue(totalLAPICallsCounter)
	// fmt.Println("number", number)

	metrics.Metrics = append(metrics.Metrics, &models.DetailedMetrics{
		Meta: &models.MetricsMeta{
			UtcNowTimestamp:   ptr.Of(time.Now().Unix()),
			WindowSizeSeconds: ptr.Of(int64(m.interval.Seconds())),
		},
		Items: items,
	})
}

func (m *metricsProvider) run(ctx context.Context, startedAt time.Time) error {
	if m.interval == 0 {
		m.logger.Info("usage metrics disabled")
		return nil
	}

	m.startedAtTimestamp = startedAt.Unix()

	ticker := time.NewTicker(m.interval)

	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("metric provider halted: %w", err)
			}

			return errors.New("metric provider halted")
		case <-ticker.C:
			met := m.metricsPayload()

			ctxTime, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			_, resp, err := m.apiClient.UsageMetrics.Add(ctxTime, met)
			switch {
			case errors.Is(err, context.DeadlineExceeded):
				m.logger.Warn("timeout sending metrics")
				continue
			case resp != nil && resp.Response != nil && resp.Response.StatusCode == http.StatusNotFound:
				m.logger.Warn("metrics endpoint not found, older LAPI?")
				continue
			case err != nil:
				m.logger.Warn("failed to send metrics: %s", zap.Error(err))
				continue
			}

			if resp.Response.StatusCode != http.StatusCreated {
				m.logger.Warn("failed to send metrics", zap.Int("status", resp.Response.StatusCode))
				continue
			}

			m.logger.Debug("usage metrics sent")
		}
	}
}

func (b *Bouncer) startMetricsProvider(ctx context.Context) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		b.logger.Debug("starting metrics provider", b.zapField())
		if err := b.metricsProvider.run(ctx, b.startedAt); err != nil {
			if err.Error() == "metric provider halted" { // TODO: don't rely on the error being returned
				b.logger.Info("metrics provider stopped", b.zapField())
			} else {
				b.logger.Error("failed running metrics provider", b.zapField(), zap.Error(err))
			}
		}
	}()
}
