package otelsetup

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	loggerglobal "go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/trace"
)

// defaultLevel backs the process default logger. Held in a LevelVar so SetLevel
// can retune verbosity without rebuilding the handler chain, which would
// discard the OTLP bridge.
var defaultLevel = new(slog.LevelVar)

// installedDefault remembers the last SetDefaultJSONLogger arguments so Init can
// reinstall the default with the OTLP bridge attached, whichever order the two
// are called in. Nil until SetDefaultJSONLogger runs, so Init never touches a
// default logger this package did not install.
var installedDefault struct {
	mu   sync.Mutex
	conf *loggerConfig
}

// loggerConfig is the resolved set of logger options.
type loggerConfig struct {
	serviceName string
	writer      io.Writer
}

// LoggerOption customises the JSON logger constructors.
type LoggerOption func(*loggerConfig)

// WithWriter redirects JSON log output, which defaults to stdout (journald).
// viperblock's nbdkit plugin needs stderr: nbdkit repoints a plugin's fd 1 at
// /dev/null but leaves fd 2 on the parent's journald socket, so a stdout logger
// discards everything the plugin emits.
func WithWriter(w io.Writer) LoggerOption {
	return func(c *loggerConfig) { c.writer = w }
}

// NewJSONLogger builds a *slog.Logger writing JSON at the given level, with
// trace_id/span_id stamping. If Init already installed a real OTLP
// LoggerProvider the logger also fans out to it, scoped to serviceName. Unlike
// SetDefaultJSONLogger this never touches slog.SetDefault, so it is safe to call
// from library code that only wants its own scoped logger.
func NewJSONLogger(serviceName string, level slog.Leveler, opts ...LoggerOption) *slog.Logger {
	return slog.New(newHandler(resolveLoggerConfig(serviceName, opts), level))
}

// SetDefaultJSONLogger installs the process-wide slog default built by
// NewJSONLogger. Safe to call before or after Init: Init reinstalls the default
// once the LoggerProvider exists, so the bridge is attached either way. level is
// snapshotted — use SetLevel to change verbosity afterwards. Callers must invoke
// this explicitly (standalone entrypoints only), never from a constructor an
// embedder might call, or it silently hijacks the host process's own logger.
func SetDefaultJSONLogger(serviceName string, level slog.Leveler, opts ...LoggerOption) {
	conf := resolveLoggerConfig(serviceName, opts)
	defaultLevel.Set(level.Level())

	installedDefault.mu.Lock()
	installedDefault.conf = conf
	installedDefault.mu.Unlock()

	slog.SetDefault(slog.New(newHandler(conf, defaultLevel)))
}

// SetLevel retunes the default logger's level in place, leaving the handler
// chain intact. Callers that only need to adjust verbosity must use this:
// calling SetDefaultJSONLogger again rebuilds the chain, and before Init has run
// that leaves the default unbridged.
func SetLevel(level slog.Level) { defaultLevel.Set(level) }

// refreshDefaultLogger rebuilds the process default so its OTLP bridge picks up
// a LoggerProvider installed after SetDefaultJSONLogger ran.
func refreshDefaultLogger() {
	installedDefault.mu.Lock()
	conf := installedDefault.conf
	installedDefault.mu.Unlock()
	if conf == nil {
		return
	}
	slog.SetDefault(slog.New(newHandler(conf, defaultLevel)))
}

// resolveLoggerConfig applies opts over the stdout default.
func resolveLoggerConfig(serviceName string, opts []LoggerOption) *loggerConfig {
	conf := &loggerConfig{serviceName: serviceName, writer: os.Stdout}
	for _, opt := range opts {
		opt(conf)
	}
	return conf
}

// newHandler builds the JSON handler, fanning out to the OTLP bridge when a real
// LoggerProvider is installed. Both sinks are gated at the same level: the
// bridge has no severity filter of its own, so without gating every record
// (including Debug) would ship to OTLP regardless of the configured level.
func newHandler(conf *loggerConfig, level slog.Leveler) slog.Handler {
	out := NewSlogHandler(slog.NewJSONHandler(conf.writer, &slog.HandlerOptions{
		Level: level,
	}))

	lp, ok := loggerglobal.GetLoggerProvider().(*sdklog.LoggerProvider)
	if !ok {
		return out
	}
	bridge := otelslog.NewHandler(conf.serviceName, otelslog.WithLoggerProvider(lp))
	return newFanoutHandler(out, newLevelHandler(level, bridge))
}

var _ slog.Handler = (*traceHandler)(nil)

// traceHandler stamps trace_id/span_id from the record's context onto every
// log line so any log can be pivoted to its trace in the backend.
type traceHandler struct {
	inner slog.Handler
}

// NewSlogHandler wraps inner so records logged with a context carrying an
// active span gain trace_id and span_id attributes. Records without a span
// pass through unchanged.
func NewSlogHandler(inner slog.Handler) slog.Handler {
	return &traceHandler{inner: inner}
}

func (h *traceHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.inner.Handle(ctx, r)
}

func (h *traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &traceHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *traceHandler) WithGroup(name string) slog.Handler {
	return &traceHandler{inner: h.inner.WithGroup(name)}
}

var _ slog.Handler = (*levelHandler)(nil)

// levelHandler gates inner at a minimum level. The otelslog bridge reports
// Enabled==true for every level (its BatchProcessor has no severity filter),
// so without this wrapper every Debug record would be exported to OTLP
// regardless of the configured level — and slog would never short-circuit
// Debug calls at the call site.
type levelHandler struct {
	level slog.Leveler
	inner slog.Handler
}

// newLevelHandler returns a handler that only forwards records at or above
// level to inner, regardless of what inner.Enabled reports.
func newLevelHandler(level slog.Leveler, inner slog.Handler) slog.Handler {
	return &levelHandler{level: level, inner: inner}
}

func (h *levelHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level.Level() }

func (h *levelHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

func (h *levelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelHandler{level: h.level, inner: h.inner.WithAttrs(attrs)}
}

func (h *levelHandler) WithGroup(name string) slog.Handler {
	return &levelHandler{level: h.level, inner: h.inner.WithGroup(name)}
}

var _ slog.Handler = (*fanoutHandler)(nil)

// fanoutHandler writes every record to all inner handlers, e.g. so OTLP
// export is additive to the existing stdout/journald handler rather than
// replacing it.
type fanoutHandler struct {
	handlers []slog.Handler
}

// newFanoutHandler returns a handler that fans out to all of handlers.
func newFanoutHandler(handlers ...slog.Handler) slog.Handler {
	return &fanoutHandler{handlers: handlers}
}

func (h *fanoutHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, inner := range h.handlers {
		if inner.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h *fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs error
	for _, inner := range h.handlers {
		if inner.Enabled(ctx, r.Level) {
			errs = errors.Join(errs, inner.Handle(ctx, r.Clone()))
		}
	}
	return errs
}

func (h *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(h.handlers))
	for i, inner := range h.handlers {
		next[i] = inner.WithAttrs(attrs)
	}
	return &fanoutHandler{handlers: next}
}

func (h *fanoutHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(h.handlers))
	for i, inner := range h.handlers {
		next[i] = inner.WithGroup(name)
	}
	return &fanoutHandler{handlers: next}
}
