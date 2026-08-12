package otelsetup

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace/noop"

	loggerglobal "go.opentelemetry.io/otel/log/global"
	lognoop "go.opentelemetry.io/otel/log/noop"
)

// endpointEnvKeys is every OTLP endpoint variable exportEnabled consults, so
// tests can clear the whole set rather than whichever ones they remember.
var endpointEnvKeys = []string{
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
	"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
}

func clearEndpointEnv(t *testing.T) {
	t.Helper()
	for _, key := range endpointEnvKeys {
		t.Setenv(key, "")
	}
}

func TestInitWithoutEndpointIsNoop(t *testing.T) {
	clearEndpointEnv(t)
	// Pin a known no-op provider: the otel global delegator cannot be reset
	// once another test has installed a real provider.
	otel.SetTracerProvider(noop.NewTracerProvider())

	shutdown, err := Init(context.Background(), "test-svc")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, span := otel.Tracer("test").Start(context.Background(), "op")
	defer span.End()
	if span.SpanContext().IsValid() {
		t.Error("expected no-op tracer without endpoint, got recording span")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

func TestInitWithEndpointInstallsProviders(t *testing.T) {
	// Point at a dead endpoint: exporters dial lazily, so Init must still
	// succeed and install real (recording) providers.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	prevTracer := otel.GetTracerProvider()
	prevMeter := otel.GetMeterProvider()
	defer otel.SetTracerProvider(prevTracer)
	defer otel.SetMeterProvider(prevMeter)

	shutdown, err := Init(context.Background(), "test-svc")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, span := otel.Tracer("test").Start(context.Background(), "op")
	if !span.SpanContext().IsValid() {
		t.Error("expected recording tracer with endpoint set, got no-op span")
	}
	span.End()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// Flush hits the dead endpoint; only assert it returns rather than hangs.
	_ = shutdown(ctx)
}

// TestWithoutTracingInstallsNoTracerOrPropagator pins viperblock's contract:
// embedded in a host that already owns tracing, Init must leave both the
// TracerProvider and the propagator exactly as the host set them.
func TestWithoutTracingInstallsNoTracerOrPropagator(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")

	prevTracer := otel.GetTracerProvider()
	prevMeter := otel.GetMeterProvider()
	prevProp := otel.GetTextMapPropagator()
	defer otel.SetTracerProvider(prevTracer)
	defer otel.SetMeterProvider(prevMeter)
	defer otel.SetTextMapPropagator(prevProp)

	sentinel := propagation.NewCompositeTextMapPropagator()
	otel.SetTextMapPropagator(sentinel)
	otel.SetTracerProvider(noop.NewTracerProvider())

	shutdown, err := Init(context.Background(), "test-svc", WithoutTracing(), WithoutRuntimeMetrics())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = shutdown(ctx)
	}()

	_, span := otel.Tracer("test").Start(context.Background(), "op")
	defer span.End()
	if span.SpanContext().IsValid() {
		t.Error("WithoutTracing installed a recording TracerProvider")
	}
	if len(otel.GetTextMapPropagator().Fields()) != 0 {
		t.Errorf("WithoutTracing replaced the host propagator, fields = %v",
			otel.GetTextMapPropagator().Fields())
	}
	// Logs and metrics must still be wired: WithoutTracing drops tracing only.
	if _, ok := loggerglobal.GetLoggerProvider().(*sdklog.LoggerProvider); !ok {
		t.Errorf("expected a real sdk/log LoggerProvider, got %T", loggerglobal.GetLoggerProvider())
	}
}

func TestExportEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"nothing set", nil, false},
		{"endpoint set", map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317"}, true},
		{"traces endpoint only", map[string]string{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://localhost:4317"}, true},
		{"metrics endpoint only", map[string]string{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "http://localhost:4317"}, true},
		{"logs endpoint only", map[string]string{"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT": "http://localhost:4317"}, true},
		{"disabled overrides endpoint", map[string]string{
			"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4317",
			"OTEL_SDK_DISABLED":           "true",
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range append(endpointEnvKeys, "OTEL_SDK_DISABLED") {
				t.Setenv(key, tt.env[key])
			}
			if got := exportEnabled(); got != tt.want {
				t.Errorf("exportEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceAttributes(t *testing.T) {
	t.Setenv("MULGA_ENV", "env19")
	t.Setenv("MULGA_SOURCE", "ci")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "ci.run_id=12345")

	res, err := newResource(context.Background(), "test-svc", nil)
	if err != nil {
		t.Fatalf("newResource: %v", err)
	}
	got := map[string]string{}
	for _, kv := range res.Attributes() {
		got[string(kv.Key)] = kv.Value.String()
	}
	for key, want := range map[string]string{
		"service.name":           "test-svc",
		"mulga.env":              "env19",
		"deployment.environment": "env19",
		"mulga.source":           "ci",
		"ci.run_id":              "12345",
	} {
		if got[key] != want {
			t.Errorf("resource attr %s = %q, want %q", key, got[key], want)
		}
	}
	if got["host.name"] == "" {
		t.Error("resource attr host.name missing")
	}
}

// TestDeploymentEnvFallback covers spinifex, whose CI names the environment
// SPINIFEX_CI_ENV rather than MULGA_ENV. MULGA_ENV must still win when both
// are set.
func TestDeploymentEnvFallback(t *testing.T) {
	tests := []struct {
		name      string
		mulgaEnv  string
		fallback  string
		fallbacks []string
		want      string
	}{
		{"neither set", "", "", []string{"SPINIFEX_CI_ENV"}, ""},
		{"mulga env only", "env19", "", []string{"SPINIFEX_CI_ENV"}, "env19"},
		{"fallback only", "", "ci7", []string{"SPINIFEX_CI_ENV"}, "ci7"},
		{"mulga env wins", "env19", "ci7", []string{"SPINIFEX_CI_ENV"}, "env19"},
		{"fallback not consulted", "", "ci7", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MULGA_ENV", tt.mulgaEnv)
			t.Setenv("SPINIFEX_CI_ENV", tt.fallback)
			if got := deploymentEnv(tt.fallbacks); got != tt.want {
				t.Errorf("deploymentEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestInitWithoutEndpointInstallsNoLoggerProvider is the prod-safety
// guarantee: with no OTLP endpoint configured, Init must not install a
// LoggerProvider — the global stays whatever was there before.
func TestInitWithoutEndpointInstallsNoLoggerProvider(t *testing.T) {
	clearEndpointEnv(t)

	prevLP := loggerglobal.GetLoggerProvider()
	defer loggerglobal.SetLoggerProvider(prevLP)
	sentinelLP := lognoop.NewLoggerProvider()
	loggerglobal.SetLoggerProvider(sentinelLP)

	shutdown, err := Init(context.Background(), "test-svc")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	if _, ok := loggerglobal.GetLoggerProvider().(lognoop.LoggerProvider); !ok {
		t.Errorf("expected global LoggerProvider to remain the noop sentinel, got %T", loggerglobal.GetLoggerProvider())
	}
}

// TestInitWithEndpointInstallsLoggerProvider proves the same export gate
// installs a real sdk/log LoggerProvider once an OTLP endpoint is configured.
func TestInitWithEndpointInstallsLoggerProvider(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	prevLP := loggerglobal.GetLoggerProvider()
	defer loggerglobal.SetLoggerProvider(prevLP)
	prevTracer := otel.GetTracerProvider()
	prevMeter := otel.GetMeterProvider()
	defer otel.SetTracerProvider(prevTracer)
	defer otel.SetMeterProvider(prevMeter)

	shutdown, err := Init(context.Background(), "test-svc")
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	if _, ok := loggerglobal.GetLoggerProvider().(*sdklog.LoggerProvider); !ok {
		t.Errorf("expected a real sdk/log LoggerProvider, got %T", loggerglobal.GetLoggerProvider())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = shutdown(ctx)
}
