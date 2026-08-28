// Package otelsetup configures OpenTelemetry tracing, metrics and logging for
// Mulga services. Export is gated on the standard OTLP environment variables;
// with no endpoint configured Init is a functional no-op, so instrumented
// binaries ship everywhere at zero cost. The installed MeterProvider also
// carries a view that gives every second-unit histogram explicit bucket
// boundaries, because the SDK default boundaries are a millisecond scale and
// silently collapse second-valued latencies into a single bucket.
package otelsetup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	otelruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	loggerglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const shutdownTimeout = 10 * time.Second

// initConfig is the resolved set of Init options.
type initConfig struct {
	tracing        bool
	runtimeMetrics bool
	envFallbacks   []string
}

// Option customises Init for services that cannot take the default bootstrap.
type Option func(*initConfig)

// WithoutTracing skips the TracerProvider and the W3C propagator. For services
// embedded in a host process that already owns tracing (viperblock inside
// spinifex), where installing the globals would clobber the host's own.
func WithoutTracing() Option {
	return func(c *initConfig) { c.tracing = false }
}

// WithoutRuntimeMetrics skips Go runtime instrumentation.
func WithoutRuntimeMetrics() Option {
	return func(c *initConfig) { c.runtimeMetrics = false }
}

// WithEnvironmentFallback names extra environment variables consulted, in
// order, for the deployment environment when MULGA_ENV is unset.
func WithEnvironmentFallback(vars ...string) Option {
	return func(c *initConfig) { c.envFallbacks = append(c.envFallbacks, vars...) }
}

// Init installs global tracer, meter and logger providers exporting OTLP over
// gRPC, plus the W3C trace-context propagator. The returned shutdown func
// flushes and stops every installed provider; it is always safe to call. When
// no OTLP endpoint is configured (or OTEL_SDK_DISABLED=true) only the
// propagator is installed and the globals stay no-op.
func Init(ctx context.Context, serviceName string, opts ...Option) (func(context.Context) error, error) {
	cfg := initConfig{tracing: true, runtimeMetrics: true}
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.tracing {
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{}))
	}

	if !exportEnabled() {
		return func(context.Context) error { return nil }, nil
	}

	res, err := newResource(ctx, serviceName, cfg.envFallbacks)
	if err != nil {
		return nil, fmt.Errorf("otel resource for %s: %w", serviceName, err)
	}

	// Collected in install order so a later exporter failure can unwind the
	// providers already made global, leaving nothing half-started.
	var installed []func(context.Context) error

	if cfg.tracing {
		traceExp, err := otlptracegrpc.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("otlp trace exporter for %s: %w", serviceName, err)
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(traceExp),
			sdktrace.WithResource(res),
			sdktrace.WithSampler(rootSampler()),
		)
		otel.SetTracerProvider(tp)
		installed = append(installed, tp.Shutdown)
	}

	metricExp, err := otlpmetricgrpc.New(ctx)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("otlp metric exporter for %s: %w", serviceName, err),
			shutdownAll(installed))
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
		sdkmetric.WithView(secondsHistogramView()),
	)
	otel.SetMeterProvider(mp)
	installed = append(installed, mp.Shutdown)

	logExp, err := otlploggrpc.New(ctx)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("otlp log exporter for %s: %w", serviceName, err),
			shutdownAll(installed))
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(newUTF8Processor(sdklog.NewBatchProcessor(logExp))),
	)
	loggerglobal.SetLoggerProvider(lp)
	installed = append(installed, lp.Shutdown)

	if cfg.runtimeMetrics {
		if err := otelruntime.Start(); err != nil {
			slog.Warn("otel runtime metrics disabled", "err", err)
		}
	}

	// Attaches the OTLP bridge to a default logger installed before Init, so
	// the two are order-independent. No-op otherwise.
	refreshDefaultLogger()

	shutdown := func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, shutdownTimeout)
		defer cancel()
		var errs error
		for _, stop := range installed {
			errs = errors.Join(errs, stop(ctx))
		}
		return errs
	}
	return shutdown, nil
}

// shutdownAll stops providers installed before a failing exporter, on its own
// context: the caller's may already be cancelled by whatever caused the error.
func shutdownAll(installed []func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	var errs error
	for _, stop := range installed {
		errs = errors.Join(errs, stop(ctx))
	}
	return errs
}

// secondsHistogramBoundaries bounds every second-unit duration histogram
// installed through Init, across every Mulga service. The SDK's default
// boundaries run 0..10000 and only make sense for a millisecond scale: every
// second-valued sample below 5 lands in the first bucket and every
// percentile reads back as that bucket's centroid. These match predastore's
// own per-instrument boundaries as a prefix, with 30 added as a wider top
// bucket for operations slower than a shard read.
var secondsHistogramBoundaries = []float64{
	0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

// secondsHistogramView applies secondsHistogramBoundaries to every
// second-unit histogram the MeterProvider collects, regardless of which
// service or instrument records it. Fixing this at the provider, rather
// than per instrument, means the boundaries apply to instruments nobody
// has written yet, and no call site has to remember to set them.
func secondsHistogramView() sdkmetric.View {
	return sdkmetric.NewView(
		sdkmetric.Instrument{
			Kind: sdkmetric.InstrumentKindHistogram,
			Unit: "s",
		},
		sdkmetric.Stream{
			Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: secondsHistogramBoundaries,
			},
		},
	)
}

// rootSampler samples locally-rooted traces at MULGA_ROOT_TRACE_RATIO
// (default 1.0) while always honoring an inbound sampled traceparent. Lets
// chatty services (background chunk I/O has no caller trace) shed root noise
// without losing any request-linked span.
func rootSampler() sdktrace.Sampler {
	ratio := 1.0
	if v := os.Getenv("MULGA_ROOT_TRACE_RATIO"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
			ratio = f
		} else {
			slog.Warn("invalid MULGA_ROOT_TRACE_RATIO, using 1.0", "value", v)
		}
	}
	return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
}

// exportEnabled reports whether any standard OTLP endpoint is configured and
// the SDK is not explicitly disabled.
func exportEnabled() bool {
	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return false
	}
	for _, key := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

// newResource builds the service resource: identity attrs set here, plus
// host detection and anything in OTEL_RESOURCE_ATTRIBUTES (ci.run_id etc.).
func newResource(ctx context.Context, serviceName string, envFallbacks []string) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{semconv.ServiceName(serviceName)}
	if v := buildVersion(); v != "" {
		attrs = append(attrs, semconv.ServiceVersion(v))
	}
	if env := deploymentEnv(envFallbacks); env != "" {
		// deployment.environment maps to service.environment in Elastic APM,
		// enabling the native environment selector across the APM UI.
		attrs = append(attrs,
			attribute.String("mulga.env", env),
			semconv.DeploymentEnvironment(env))
	}
	if src := os.Getenv("MULGA_SOURCE"); src != "" {
		attrs = append(attrs, attribute.String("mulga.source", src))
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithHost(),
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attrs...),
	)
	// Schema-URL conflicts between detectors still yield a usable merged
	// resource; only a nil resource is fatal.
	if err != nil && res == nil {
		return nil, err
	}
	return res, nil
}

// deploymentEnv reads MULGA_ENV, then any caller-supplied fallbacks in order,
// for services whose CI names the deployment environment differently.
func deploymentEnv(fallbacks []string) string {
	if env := os.Getenv("MULGA_ENV"); env != "" {
		return env
	}
	for _, key := range fallbacks {
		if env := os.Getenv(key); env != "" {
			return env
		}
	}
	return ""
}

// buildVersion returns the module version or embedded VCS revision, if any.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 12 {
			return s.Value[:12]
		}
	}
	return ""
}
