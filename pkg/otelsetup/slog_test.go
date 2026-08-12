package otelsetup

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace"

	loggerglobal "go.opentelemetry.io/otel/log/global"
	lognoop "go.opentelemetry.io/otel/log/noop"
)

// resetLoggerState restores the process default logger, this package's memory
// of it, and the shared level var, so a test that installs a default does not
// leak into the next one.
func resetLoggerState(t *testing.T) {
	t.Helper()
	prevHandler := slog.Default().Handler()
	prevLevel := defaultLevel.Level()
	installedDefault.mu.Lock()
	prevConf := installedDefault.conf
	installedDefault.mu.Unlock()

	t.Cleanup(func() {
		slog.SetDefault(slog.New(prevHandler))
		defaultLevel.Set(prevLevel)
		installedDefault.mu.Lock()
		installedDefault.conf = prevConf
		installedDefault.mu.Unlock()
	})
}

// installRecordingProvider makes a real sdk/log LoggerProvider global, backed
// by a synchronous recording exporter, standing in for the OTLP gRPC exporter
// Init would install.
func installRecordingProvider(t *testing.T, opts ...sdklog.LoggerProviderOption) *recordingLogExporter {
	t.Helper()
	exp := &recordingLogExporter{}
	lp := sdklog.NewLoggerProvider(
		append(opts, sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))...)

	prevLP := loggerglobal.GetLoggerProvider()
	loggerglobal.SetLoggerProvider(lp)
	t.Cleanup(func() {
		loggerglobal.SetLoggerProvider(prevLP)
		_ = lp.Shutdown(context.Background())
	})
	return exp
}

// installNoopProvider makes the global LoggerProvider a no-op, i.e. the state
// left behind when Init runs with no OTLP endpoint configured.
func installNoopProvider(t *testing.T) {
	t.Helper()
	prevLP := loggerglobal.GetLoggerProvider()
	loggerglobal.SetLoggerProvider(lognoop.NewLoggerProvider())
	t.Cleanup(func() { loggerglobal.SetLoggerProvider(prevLP) })
}

// testSpanContext is a valid, sampled span context for trace-stamping assertions.
func testSpanContext() trace.SpanContext {
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		SpanID:     trace.SpanID{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02},
		TraceFlags: trace.FlagsSampled,
	})
}

// TestBridgeScopeIsServiceName is the defect this package was carrying: the
// otelslog bridge scope was hardcoded to "predastore", so every consumer's logs
// arrived in the sink under predastore's instrumentation scope regardless of
// the service.name on the resource.
func TestBridgeScopeIsServiceName(t *testing.T) {
	for _, serviceName := range []string{"predastore", "northstar", "spinifex-daemon", "viperblockd"} {
		t.Run(serviceName, func(t *testing.T) {
			resetLoggerState(t)
			exp := installRecordingProvider(t)

			NewJSONLogger(serviceName, slog.LevelInfo, WithWriter(&bytes.Buffer{})).Info("scoped")

			records := exp.snapshot()
			if len(records) != 1 {
				t.Fatalf("got %d exported records, want 1", len(records))
			}
			if got := records[0].InstrumentationScope().Name; got != serviceName {
				t.Errorf("instrumentation scope = %q, want %q", got, serviceName)
			}
		})
	}
}

// TestBridgeIsLevelGated pins the gate the otelslog bridge does not have of its
// own: it reports Enabled==true for every level, so an ungated bridge ships
// Debug to the sink even when the service is configured at Info.
func TestBridgeIsLevelGated(t *testing.T) {
	resetLoggerState(t)
	exp := installRecordingProvider(t)

	var buf bytes.Buffer
	logger := NewJSONLogger("test-svc", slog.LevelInfo, WithWriter(&buf))

	logger.Debug("below level")
	logger.Info("at level")

	records := exp.snapshot()
	if len(records) != 1 {
		t.Fatalf("got %d exported records, want 1 (Debug must not reach OTLP at Info)", len(records))
	}
	if got := records[0].Body().AsString(); got != "at level" {
		t.Errorf("exported record body = %q, want %q", got, "at level")
	}
	if bytes.Contains(buf.Bytes(), []byte("below level")) {
		t.Errorf("Debug reached the JSON sink at Info level: %s", buf.String())
	}
}

// TestNewJSONLoggerUsesCallerLevel proves per-logger levels are independent of
// the process default. viperblock builds an Error-level logger per volume while
// the daemon default stays at Info.
func TestNewJSONLoggerUsesCallerLevel(t *testing.T) {
	resetLoggerState(t)
	installNoopProvider(t)
	SetLevel(slog.LevelDebug)

	var buf bytes.Buffer
	NewJSONLogger("test-svc", slog.LevelError, WithWriter(&buf)).Info("suppressed")

	if buf.Len() != 0 {
		t.Errorf("Error-level logger emitted an Info record: %s", buf.String())
	}
}

// TestWithWriterRedirectsOutput pins the option viperblock's nbdkit plugin
// depends on: nbdkit sends a plugin's stdout to /dev/null, so the plugin must
// be able to move its JSON lines to stderr.
func TestWithWriterRedirectsOutput(t *testing.T) {
	resetLoggerState(t)
	installNoopProvider(t)

	var buf bytes.Buffer
	NewJSONLogger("viperblockd", slog.LevelInfo, WithWriter(&buf)).Info("seal probe")

	if !bytes.Contains(buf.Bytes(), []byte("seal probe")) {
		t.Errorf("log line missing from the configured writer: %s", buf.String())
	}
}

// TestSetDefaultJSONLoggerNoLoggerProviderIsPlainHandler is the prod-safety
// guarantee: with no real LoggerProvider installed, SetDefaultJSONLogger must
// produce a plain JSON default and never wrap it in a fanoutHandler.
func TestSetDefaultJSONLoggerNoLoggerProviderIsPlainHandler(t *testing.T) {
	resetLoggerState(t)
	installNoopProvider(t)

	SetDefaultJSONLogger("test-svc", slog.LevelInfo)

	if _, ok := slog.Default().Handler().(*fanoutHandler); ok {
		t.Error("expected a plain handler without a real LoggerProvider, got fanoutHandler")
	}
}

// TestSetDefaultJSONLoggerBridgesWithoutClobbering exercises the wiring Init
// installs (resource -> LoggerProvider -> otelslog bridge) via a recording
// exporter. It proves exported records carry the full resource (incl. ci.run_id
// from OTEL_RESOURCE_ATTRIBUTES) and the logging context's trace_id, that JSON
// output is preserved alongside the bridge, and that a second
// SetDefaultJSONLogger call still exports rather than clobbering the bridge.
func TestSetDefaultJSONLoggerBridgesWithoutClobbering(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "ci.run_id=TESTRUN")
	resetLoggerState(t)

	res, err := newResource(context.Background(), "predastore", nil)
	if err != nil {
		t.Fatalf("newResource: %v", err)
	}
	exp := installRecordingProvider(t, sdklog.WithResource(res))

	var buf bytes.Buffer
	SetDefaultJSONLogger("predastore", slog.LevelInfo, WithWriter(&buf))
	// A *fanoutHandler default proves both the JSON handler and the OTLP bridge
	// are wired in together, not one replacing the other.
	if _, ok := slog.Default().Handler().(*fanoutHandler); !ok {
		t.Fatalf("expected fanoutHandler once a real LoggerProvider is installed, got %T", slog.Default().Handler())
	}

	sc := testSpanContext()
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	slog.InfoContext(ctx, "first record")

	// Mirrors an entrypoint re-asserting its level, e.g. northstar calling this
	// again from its config reload path.
	SetDefaultJSONLogger("predastore", slog.LevelInfo, WithWriter(&buf))
	if _, ok := slog.Default().Handler().(*fanoutHandler); !ok {
		t.Fatalf("expected fanoutHandler to survive a second SetDefaultJSONLogger call, got %T", slog.Default().Handler())
	}
	slog.InfoContext(ctx, "second record")

	if !bytes.Contains(buf.Bytes(), []byte("first record")) ||
		!bytes.Contains(buf.Bytes(), []byte("second record")) {
		t.Errorf("JSON sink lost records alongside the bridge: %s", buf.String())
	}

	records := exp.snapshot()
	if len(records) != 2 {
		t.Fatalf("got %d exported records, want 2 (bridge should survive repeated SetDefaultJSONLogger calls)", len(records))
	}
	for i, rec := range records {
		if rec.TraceID() != sc.TraceID() {
			t.Errorf("record %d TraceID = %s, want %s", i, rec.TraceID(), sc.TraceID())
		}
		attrs := map[string]string{}
		for _, kv := range rec.Resource().Attributes() {
			attrs[string(kv.Key)] = kv.Value.String()
		}
		if attrs["service.name"] != "predastore" {
			t.Errorf("record %d resource service.name = %q, want predastore", i, attrs["service.name"])
		}
		if attrs["ci.run_id"] != "TESTRUN" {
			t.Errorf("record %d resource ci.run_id = %q, want TESTRUN", i, attrs["ci.run_id"])
		}
	}
}

// TestInitAttachesBridgeToExistingDefault covers spinifex's ordering, where the
// default logger is installed before Init so startup lines are already JSON.
// Init must bolt the bridge onto it; previously each service needed its own
// addFanoutHandler call to achieve this.
func TestInitAttachesBridgeToExistingDefault(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	resetLoggerState(t)
	installNoopProvider(t)

	SetDefaultJSONLogger("spinifex-daemon", slog.LevelInfo, WithWriter(&bytes.Buffer{}))
	if _, ok := slog.Default().Handler().(*fanoutHandler); ok {
		t.Fatal("bridge attached before a real LoggerProvider existed")
	}

	shutdown, err := Init(context.Background(), "spinifex-daemon", WithoutRuntimeMetrics())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = shutdown(ctx)
	}()

	if _, ok := slog.Default().Handler().(*fanoutHandler); !ok {
		t.Errorf("Init did not attach the bridge to the existing default, got %T", slog.Default().Handler())
	}
}

// TestInitLeavesForeignDefaultAlone is the other half: Init must only rebuild a
// default this package installed. An embedder's own logger stays untouched.
func TestInitLeavesForeignDefaultAlone(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	resetLoggerState(t)

	installedDefault.mu.Lock()
	installedDefault.conf = nil
	installedDefault.mu.Unlock()

	foreign := &recordingSlogHandler{}
	slog.SetDefault(slog.New(foreign))

	shutdown, err := Init(context.Background(), "test-svc", WithoutRuntimeMetrics())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_ = shutdown(ctx)
	}()

	if slog.Default().Handler() != slog.Handler(foreign) {
		t.Errorf("Init replaced a default logger it did not install, got %T", slog.Default().Handler())
	}
}

// TestSetLevelRetunesBothSinks covers spinifex's gateway, which changes
// verbosity long after startup. Reinstalling the default there would silently
// unbolt the OTLP bridge, so SetLevel must retune the live chain — and retune
// the bridge's gate too, not just the JSON handler.
func TestSetLevelRetunesBothSinks(t *testing.T) {
	resetLoggerState(t)
	exp := installRecordingProvider(t)

	var buf bytes.Buffer
	SetDefaultJSONLogger("awsgw", slog.LevelInfo, WithWriter(&buf))
	handler := slog.Default().Handler()

	slog.Debug("before")

	SetLevel(slog.LevelDebug)
	slog.Debug("after")

	if slog.Default().Handler() != handler {
		t.Error("SetLevel rebuilt the handler chain, which would drop the OTLP bridge")
	}
	if !bytes.Contains(buf.Bytes(), []byte("after")) {
		t.Errorf("Debug not logged to JSON sink after level lowered: %s", buf.String())
	}
	if bytes.Contains(buf.Bytes(), []byte("before")) {
		t.Errorf("Debug logged to JSON sink before level lowered: %s", buf.String())
	}

	records := exp.snapshot()
	if len(records) != 1 {
		t.Fatalf("got %d exported records, want 1 (only the post-SetLevel Debug)", len(records))
	}
	if got := records[0].Body().AsString(); got != "after" {
		t.Errorf("exported record body = %q, want %q", got, "after")
	}
}

// recordingLogExporter is a minimal sdk/log.Exporter that records every
// exported record for assertions, used since v0.20.0 ships no built-in
// in-memory test exporter for external consumers.
type recordingLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

var _ sdklog.Exporter = (*recordingLogExporter)(nil)

func (e *recordingLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range records {
		e.records = append(e.records, r.Clone())
	}
	return nil
}

func (e *recordingLogExporter) Shutdown(context.Context) error   { return nil }
func (e *recordingLogExporter) ForceFlush(context.Context) error { return nil }

func (e *recordingLogExporter) snapshot() []sdklog.Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]sdklog.Record(nil), e.records...)
}

// recordingSlogHandler is a bare slog.Handler that records whether Handle
// was called, standing in for the pre-existing stdout/journald handler in
// fan-out tests.
type recordingSlogHandler struct {
	mu     sync.Mutex
	called int
}

var _ slog.Handler = (*recordingSlogHandler)(nil)

func (h *recordingSlogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingSlogHandler) Handle(context.Context, slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.called++
	return nil
}

func (h *recordingSlogHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingSlogHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingSlogHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.called
}

// TestFanoutHandlerWritesToAllHandlers proves the existing stdout/journald
// handler still fires when the OTLP bridge handler is fanned in alongside it.
func TestFanoutHandlerWritesToAllHandlers(t *testing.T) {
	stdout := &recordingSlogHandler{}
	bridge := &recordingSlogHandler{}
	logger := slog.New(newFanoutHandler(stdout, bridge))

	logger.Info("dual write")

	if stdout.count() != 1 {
		t.Errorf("stdout handler called %d times, want 1", stdout.count())
	}
	if bridge.count() != 1 {
		t.Errorf("bridge handler called %d times, want 1", bridge.count())
	}
}

func TestSlogHandlerStampsTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&buf, nil)))

	sc := testSpanContext()
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger.InfoContext(ctx, "with span")

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}
	if line["trace_id"] != sc.TraceID().String() {
		t.Errorf("trace_id = %v, want %s", line["trace_id"], sc.TraceID())
	}
	if line["span_id"] != sc.SpanID().String() {
		t.Errorf("span_id = %v, want %s", line["span_id"], sc.SpanID())
	}
}

func TestSlogHandlerNoSpanNoStamp(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&buf, nil)))

	logger.InfoContext(context.Background(), "no span")

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}
	if _, ok := line["trace_id"]; ok {
		t.Error("trace_id present on record without span")
	}
	if _, ok := line["span_id"]; ok {
		t.Error("span_id present on record without span")
	}
}

func TestSlogHandlerPreservesWrapperThroughWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewSlogHandler(slog.NewJSONHandler(&buf, nil))).
		With("component", "test").WithGroup("grp")

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{0xff, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		SpanID:  trace.SpanID{0xfa, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02},
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	logger.InfoContext(ctx, "wrapped", "k", "v")

	if !bytes.Contains(buf.Bytes(), []byte(sc.TraceID().String())) {
		t.Errorf("trace_id lost after With/WithGroup: %s", buf.String())
	}
}
