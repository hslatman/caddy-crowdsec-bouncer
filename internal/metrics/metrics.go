package metrics

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/go-cs-lib/ptr"
	"github.com/crowdsecurity/go-cs-lib/version"
	"github.com/hslatman/ipstore"
	"github.com/prometheus/client_golang/prometheus"
	model "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

type metricName string

var (
	activeDecisionsName                   metricName = "crowdsec_decisions_active"
	blockedRequestsCounterName            metricName = "crowdsec_requests_blocked"
	processedRequestsCounterName          metricName = "crowdsec_requests_processed"
	processedRequestsPerModuleCounterName metricName = "crowdsec_requests_processed_per_module"
	totalBouncerCallsName                 metricName = "crowdsec_bouncer_lapi_requests_total"
	totalBouncerErrorsName                metricName = "crowdsec_bouncer_lapi_requests_failures_total"
	totalAppSecCallsName                  metricName = "crowdsec_appsec_lapi_requests_total"
	totalAppSecErrorsName                 metricName = "crowdsec_appsec_lapi_requests_failures_total"
)

var (
	labelServer      = "server"
	labelOrigin      = "origin"
	labelIPType      = "ip_type"
	labelRemediation = "remediation"
	labelModule      = "module"
	labelBouncerMode = "mode"
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

func (m metricMap) registerAll(registry *prometheus.Registry) error {
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

func NewProvider(metricsRegistry, caddyMetricsRegistry *prometheus.Registry, interval time.Duration, logger *zap.Logger, userAgentName, userAgentVersion, instanceID string) (*Provider, error) {
	// bouncer metrics; provided by the go-cs-bouncer package, but overridden
	// by recreating the main bouncer logic.
	totalBouncerCallsCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(totalBouncerCallsName),
		Help: "The total number of calls to CrowdSec LAPI",
	}, []string{labelBouncerMode})
	totalBouncerErrorsCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(totalBouncerErrorsName),
		Help: "The total number of failed calls to CrowdSec LAPI",
	}, []string{labelBouncerMode})

	// appsec metrics; not provided by the go-cs-bouncer package
	totalAppSecCallsCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(totalAppSecCallsName),
		Help: "The total number of calls to the CrowdSec LAPI AppSec component",
	}, nil)
	totalAppSecErrorsCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(totalAppSecErrorsName),
		Help: "The total number of failed calls to the CrowdSec LAPI AppSec component",
	}, nil)

	// decision metrics; not provided by the go-cs-bouncer package
	activeDecisionsGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: string(activeDecisionsName),
		Help: "The current number of active decisions",
	}, []string{labelOrigin, labelIPType})
	blockedRequestsCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(blockedRequestsCounterName),
		Help: "The total number of requests blocked",
	}, []string{labelServer, labelOrigin, labelRemediation, labelIPType})
	processedRequestsCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(processedRequestsCounterName),
		Help: "The total number of requests handled",
	}, []string{labelServer, labelIPType})
	processedRequestsPerModuleCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: string(processedRequestsPerModuleCounterName),
		Help: "The total number of requests handled per module",
	}, []string{labelServer, labelModule, labelIPType})

	metricMap := &metricMap{
		activeDecisionsName: {
			Name:         "active_decisions",
			Unit:         "ip",
			Collector:    activeDecisionsGauge,
			LabelKeys:    []string{labelOrigin, labelIPType},
			LastValueMap: nil, // absolute value
			KeyFunc: func(labels []*model.LabelPair) string {
				return getLabelValue(labels, labelOrigin) + getLabelValue(labels, labelIPType)
			},
			SendToLAPI: true,
		},
		blockedRequestsCounterName: {
			Name:         "dropped",
			Unit:         "request",
			Collector:    blockedRequestsCounter,
			LabelKeys:    []string{labelServer, labelOrigin, labelRemediation, labelIPType},
			LastValueMap: make(map[string]float64),
			KeyFunc: func(labels []*model.LabelPair) string {
				return getLabelValue(labels, labelServer) + getLabelValue(labels, labelOrigin) + getLabelValue(labels, labelRemediation) + getLabelValue(labels, labelIPType)
			},
			SendToLAPI: true,
		},
		processedRequestsCounterName: {
			Name:         "processed",
			Unit:         "request",
			Collector:    processedRequestsCounter,
			LabelKeys:    []string{labelServer, labelIPType},
			LastValueMap: make(map[string]float64),
			KeyFunc: func(labels []*model.LabelPair) string {
				return getLabelValue(labels, labelServer) + getLabelValue(labels, labelIPType)
			},
			SendToLAPI: true,
		},
		processedRequestsPerModuleCounterName: {
			Name:         "processed_per_module",
			Unit:         "request",
			Collector:    processedRequestsPerModuleCounter,
			LabelKeys:    []string{labelServer, labelModule, labelIPType},
			LastValueMap: make(map[string]float64),
			KeyFunc: func(labels []*model.LabelPair) string {
				return getLabelValue(labels, labelServer) + getLabelValue(labels, labelModule) + getLabelValue(labels, labelIPType)
			},
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
	if err := metricMap.registerAll(metricsRegistry); err != nil {
		return nil, fmt.Errorf("failed registering metrics: %w", err)
	}

	// register the metrics with the Caddy metrics registry
	if err := metricMap.registerAll(caddyMetricsRegistry); err != nil {
		return nil, fmt.Errorf("failed registering metrics with Caddy registry: %w", err)
	}

	osName, osVersion := version.DetectOS()

	m := &Provider{
		interval:                          interval,
		metricMap:                         metricMap,
		metricsRegistry:                   metricsRegistry,
		caddyMetricsRegistry:              caddyMetricsRegistry,
		totalBouncerCallsCounter:          totalBouncerCallsCounter,
		totalBouncerErrorsCounter:         totalBouncerErrorsCounter,
		totalAppSecCallsCounter:           totalAppSecCallsCounter,
		totalAppSecErrorsCounter:          totalAppSecErrorsCounter,
		activeDecisionsGauge:              activeDecisionsGauge,
		blockedRequestsCounter:            blockedRequestsCounter,
		processedRequestsCounter:          processedRequestsCounter,
		processedRequestsPerModuleCounter: processedRequestsPerModuleCounter,
		bouncerType:                       userAgentName,
		bouncerVersion:                    userAgentVersion,
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

func (p *Provider) SetAPIClient(a *apiclient.ApiClient) {
	p.apiClient = a
}

type Provider struct {
	apiClient                         *apiclient.ApiClient
	interval                          time.Duration
	metricMap                         *metricMap
	metricsRegistry                   *prometheus.Registry
	caddyMetricsRegistry              *prometheus.Registry
	totalBouncerCallsCounter          *prometheus.CounterVec
	totalBouncerErrorsCounter         *prometheus.CounterVec
	totalAppSecCallsCounter           *prometheus.CounterVec
	totalAppSecErrorsCounter          *prometheus.CounterVec
	activeDecisionsGauge              *prometheus.GaugeVec
	blockedRequestsCounter            *prometheus.CounterVec
	processedRequestsCounter          *prometheus.CounterVec
	processedRequestsPerModuleCounter *prometheus.CounterVec
	logger                            *zap.Logger
	bouncerType                       string
	bouncerVersion                    string
	bouncerOS                         models.OSversion
	bouncerFeatureFlags               []string
	instanceID                        string
	startedAtTimestamp                int64
	started                           atomic.Bool
	initialMetricsSent                atomic.Bool
	lastMetricsSentAt                 time.Time
	sending                           sync.Mutex
}

func (p *Provider) metricsPayload(now time.Time) (metrics *models.AllMetrics) {
	metrics = &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{
			{
				Name: p.bouncerType,
				Type: p.bouncerType,
				BaseMetrics: models.BaseMetrics{
					Os:                  &p.bouncerOS,
					Version:             &p.bouncerVersion,
					FeatureFlags:        p.bouncerFeatureFlags,
					UtcStartupTimestamp: &p.startedAtTimestamp,
				},
			},
		},
	}

	items, err := getMetricItems(p.metricsRegistry, p.metricMap)
	if err != nil {
		p.logger.Error("failed getting metrics", zap.Error(err))
		return
	}

	windowSizeSeconds := float64(0)
	if !p.lastMetricsSentAt.IsZero() {
		windowSizeSeconds = max(math.Abs(now.Sub(p.lastMetricsSentAt).Seconds()), windowSizeSeconds)
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

var ErrProviderHalted = errors.New("metrics provider halted")

func (p *Provider) Run(ctx context.Context, startedAt time.Time) error {
	if p.started.Load() {
		return nil
	}

	if p.interval <= 0 {
		p.logger.Info("usage metrics disabled")
		return nil
	}

	if p.interval < 15*time.Minute {
		p.logger.Warn("low metrics push interval detected; CrowdSec suggest a minimum of 15 minutes", zap.Duration("interval", p.interval))
	}

	p.startedAtTimestamp = startedAt.Unix()
	p.started.Store(true)

	ticker := time.NewTicker(p.interval)

	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				p.logger.Error("metrics provider stopped", zap.Error(err))
				return nil
			}

			return ErrProviderHalted
		case <-ticker.C:
			_ = p.sendMetrics(ctx)
		}
	}
}

func (p *Provider) sendMetrics(ctx context.Context) (sent bool) {
	if !p.started.Load() { // metrics disabled, or not started (yet)
		return
	}

	p.sending.Lock()
	defer p.sending.Unlock()

	now := time.Now()
	metrics := p.metricsPayload(now)

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	_, resp, err := p.apiClient.UsageMetrics.Add(ctx, metrics)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		p.logger.Warn("timeout sending metrics")
		return
	case err != nil:
		p.logger.Warn("failed to send metrics", zap.Error(err))
		return
	case resp == nil || resp.Response == nil:
		p.logger.Warn("no response from metrics endpoint")
		return
	case resp.Response.StatusCode == http.StatusNotFound:
		p.logger.Warn("metrics endpoint not found; older LAPI?")
		return
	case resp.Response.StatusCode != http.StatusCreated:
		p.logger.Warn("failed to send metrics", zap.Int("status", resp.Response.StatusCode))
		return
	}

	sent = true
	p.lastMetricsSentAt = now

	isInitial := !p.initialMetricsSent.Load()
	if isInitial {
		p.initialMetricsSent.Store(sent)
	}

	p.logger.Debug("usage metrics sent", zap.Any("metrics", metrics), zap.Bool("initial", isInitial), zap.Time("next", now.Add(p.interval).Truncate(time.Second)))

	return
}

func (p *Provider) SendInitialMetricsOnce(ctx context.Context) {
	if p.initialMetricsSent.Load() {
		return
	}

	_ = p.sendMetrics(ctx)
}

func (p *Provider) caddyMetricsEnabled() bool {
	return p.caddyMetricsRegistry != nil
}

func (p *Provider) metricsEnabled() bool {
	return p.interval > 0
}

func (p *Provider) IncrementTotalBouncerCalls(mode string) {
	if !p.caddyMetricsEnabled() {
		return
	}

	p.totalBouncerCallsCounter.With(prometheus.Labels{labelBouncerMode: mode}).Inc()
}

func (p *Provider) IncrementTotalBouncerErrors(mode string) {
	if !p.caddyMetricsEnabled() {
		return
	}

	p.totalBouncerErrorsCounter.With(prometheus.Labels{labelBouncerMode: mode}).Inc()
}

func (p *Provider) IncrementTotalAppSecCalls() {
	if !p.caddyMetricsEnabled() {
		return
	}

	p.totalAppSecCallsCounter.With(nil).Inc()
}

func (p *Provider) IncrementTotalAppSecErrors() {
	if !p.caddyMetricsEnabled() {
		return
	}

	p.totalAppSecErrorsCounter.With(nil).Inc()
}

func toIPType(isIPv6 bool) (ipType string) {
	ipType = "ipv4"
	if isIPv6 {
		ipType = "ipv6"
	}

	return
}

type moduleCountedKey struct{}

type modules []string

func (p *Provider) IncrementProcessedRequests(ctx context.Context, server, module string, isIPv6 bool) context.Context {
	if !p.metricsEnabled() {
		return ctx
	}

	v, ok := ctx.Value(moduleCountedKey{}).(modules)
	if !ok || len(v) == 0 {
		p.incrementProcessedRequests(server, isIPv6)
		p.incrementProcessedRequestsPerModule(server, module, isIPv6) // count call from each module

		return context.WithValue(ctx, moduleCountedKey{}, modules{module})
	}

	if ok && slices.Contains(v, module) {
		return ctx // prevent counting same module multiple times
	}

	p.incrementProcessedRequestsPerModule(server, module, isIPv6) // count call from each module
	return context.WithValue(ctx, moduleCountedKey{}, append(v, module))
}

func (p *Provider) incrementProcessedRequests(server string, isIPv6 bool) {
	p.processedRequestsCounter.With(prometheus.Labels{labelServer: server, labelIPType: toIPType(isIPv6)}).Inc()
}

func (p *Provider) incrementProcessedRequestsPerModule(server, module string, isIPv6 bool) {
	p.processedRequestsPerModuleCounter.With(prometheus.Labels{labelServer: server, labelModule: module, labelIPType: toIPType(isIPv6)}).Inc()
}

func (p *Provider) IncrementBlockedRequests(server, origin, remediation string, isIPv6 bool) {
	if !p.metricsEnabled() {
		return
	}

	p.blockedRequestsCounter.With(prometheus.Labels{labelServer: server, labelOrigin: origin, labelRemediation: remediation, labelIPType: toIPType(isIPv6)}).Inc()
}

func (p *Provider) RecalculateAndRecordDecisionCounts(s *ipstore.Store[*models.Decision]) {
	if !p.metricsEnabled() {
		return
	}

	recalculateAndRecordDecisionCounts(s, p.activeDecisionsGauge)
}

type ipType string

const (
	ipv4 ipType = "ipv4"
	ipv6 ipType = "ipv6"
)

func recalculateAndRecordDecisionCounts(store *ipstore.Store[*models.Decision], gauge *prometheus.GaugeVec) {
	// initialize map, so that these origins are always
	// known and recorded
	counts := map[string]map[ipType]int{
		"CAPI":             {ipv4: 0, ipv6: 0},
		"crowdsec":         {ipv4: 0, ipv6: 0},
		"cscli":            {ipv4: 0, ipv6: 0},
		"cscli-import":     {ipv4: 0, ipv6: 0},
		"console":          {ipv4: 0, ipv6: 0},
		"appsec":           {ipv4: 0, ipv6: 0},
		"remediation_sync": {ipv4: 0, ipv6: 0},
	}

	for prefix, v := range store.All() {
		origin := *v.Origin
		isIPv6 := prefix.Bits() > 32
		n, ok := counts[origin]
		if !ok {
			n = map[ipType]int{ipv4: 0, ipv6: 0}
			counts[origin] = n
		}

		if isIPv6 {
			n[ipv6] += 1
		} else {
			n[ipv4] += 1
		}
	}

	// update the count of active decisions per origin and IP type
	for origin, tuple := range counts {
		for ipType, count := range tuple {
			gauge.With(prometheus.Labels{labelOrigin: origin, labelIPType: string(ipType)}).Set(float64(count))
		}
	}
}
