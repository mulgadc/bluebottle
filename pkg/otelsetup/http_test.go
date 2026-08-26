package otelsetup

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// withRecorder installs a recording tracer provider for the test and returns
// the recorder; the previous global provider is restored on cleanup.
func withRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	return sr
}

// flushCounter is a ResponseWriter whose Flush is observable, standing in for
// the real writer beneath the middleware.
type flushCounter struct {
	http.ResponseWriter

	flushes int
}

func (w *flushCounter) Flush() { w.flushes++ }

func TestStatusRecorderForwardsFlush(t *testing.T) {
	inner := &flushCounter{ResponseWriter: httptest.NewRecorder()}
	rec := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}

	f, ok := any(rec).(http.Flusher)
	if !ok {
		t.Fatal("statusRecorder does not satisfy http.Flusher")
	}
	f.Flush()
	if inner.flushes != 1 {
		t.Errorf("direct Flush reached inner writer %d times, want 1", inner.flushes)
	}

	if err := http.NewResponseController(rec).Flush(); err != nil {
		t.Fatalf("ResponseController.Flush: %v", err)
	}
	if inner.flushes != 2 {
		t.Errorf("ResponseController.Flush reached inner writer %d times, want 2", inner.flushes)
	}
}

func TestStatusRecorderUnwrapsToInnerWriter(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}

	u, ok := any(rec).(interface{ Unwrap() http.ResponseWriter })
	if !ok {
		t.Fatal("statusRecorder has no Unwrap method")
	}
	if u.Unwrap() != http.ResponseWriter(inner) {
		t.Error("Unwrap did not return the wrapped writer")
	}
}

// hijackWriter stands in for a writer that supports connection takeover.
type hijackWriter struct {
	http.ResponseWriter

	conn net.Conn
}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestStatusRecorderForwardsHijack(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	inner := &hijackWriter{ResponseWriter: httptest.NewRecorder(), conn: server}
	rec := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}

	h, ok := any(rec).(http.Hijacker)
	if !ok {
		t.Fatal("statusRecorder does not satisfy http.Hijacker")
	}
	conn, _, err := h.Hijack()
	if err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	if conn != server {
		t.Error("Hijack did not return the inner writer's connection")
	}
}

// readerFromWriter reports whether the sendfile-style fast path was taken.
type readerFromWriter struct {
	http.ResponseWriter

	used bool
}

func (w *readerFromWriter) ReadFrom(r io.Reader) (int64, error) {
	w.used = true
	return io.Copy(w.ResponseWriter, r)
}

// plainReader hides strings.Reader's WriteTo, which io.Copy would otherwise
// prefer over the destination's ReadFrom.
type plainReader struct{ io.Reader }

func TestStatusRecorderReadFromCountsAndDelegates(t *testing.T) {
	inner := &readerFromWriter{ResponseWriter: httptest.NewRecorder()}
	rec := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}

	n, err := io.Copy(rec, plainReader{strings.NewReader("hello world")})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if !inner.used {
		t.Error("ReadFrom fast path not delegated to the wrapped writer")
	}
	if n != 11 || rec.written != 11 {
		t.Errorf("copied = %d, written = %d, want 11 and 11", n, rec.written)
	}
}

func TestStatusRecorderReadFromWithoutFastPath(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: inner, status: http.StatusOK}

	if _, err := io.Copy(rec, plainReader{strings.NewReader("abc")}); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if got := inner.Body.String(); got != "abc" {
		t.Errorf("body = %q, want %q", got, "abc")
	}
	if rec.written != 3 {
		t.Errorf("written = %d, want 3", rec.written)
	}
}

func TestHTTPMiddlewareSpanPerRequest(t *testing.T) {
	sr := withRecorder(t)

	h := HTTPMiddleware("test-server")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !trace.SpanContextFromContext(r.Context()).IsValid() {
			t.Error("handler context has no span")
		}
		w.WriteHeader(http.StatusTeapot)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/foo", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "POST /foo" {
		t.Errorf("span name = %q, want %q", span.Name(), "POST /foo")
	}
	got := map[string]string{}
	for _, kv := range span.Attributes() {
		got[string(kv.Key)] = kv.Value.String()
	}
	if got["http.response.status_code"] != "418" {
		t.Errorf("status attr = %q, want 418", got["http.response.status_code"])
	}
	if got["server.name"] != "test-server" {
		t.Errorf("server.name = %q", got["server.name"])
	}
	if span.Status().Code == codes.Error {
		t.Error("4xx must not mark span as error")
	}
}

func TestHTTPMiddleware5xxSetsErrorStatus(t *testing.T) {
	sr := withRecorder(t)

	h := HTTPMiddleware("test-server")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	if spans[0].Status().Code != codes.Error {
		t.Errorf("span status = %v, want Error on 5xx", spans[0].Status().Code)
	}
}

// TestOutcomeForStatusSeparatesClientErrors guards the classification the
// dashboards split on: 4xx must not be counted as success (which hid every
// 401 and 404) and must not be folded into error, which is server fault.
func TestOutcomeForStatusSeparatesClientErrors(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{status: http.StatusOK, want: "success"},
		{status: http.StatusNoContent, want: "success"},
		{status: http.StatusNotModified, want: "success"},
		{status: http.StatusBadRequest, want: "client_error"},
		{status: http.StatusUnauthorized, want: "client_error"},
		{status: http.StatusForbidden, want: "client_error"},
		{status: http.StatusNotFound, want: "client_error"},
		{status: http.StatusInternalServerError, want: "error"},
		{status: http.StatusBadGateway, want: "error"},
	}

	for _, tc := range tests {
		if got := OutcomeForStatus(tc.status); got != tc.want {
			t.Errorf("OutcomeForStatus(%d) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

// TestHTTPMiddleware4xxIsNotSpanError pins the split between the two signals:
// a client error is a distinct metric outcome but must not mark the span
// failed, or every 404 would show as a broken request in the trace view.
func TestHTTPMiddleware4xxIsNotSpanError(t *testing.T) {
	sr := withRecorder(t)

	h := HTTPMiddleware("test")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/latest/api/token", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := spans[0].Status().Code; got == codes.Error {
		t.Errorf("span status = %v, want not Error for a 4xx", got)
	}
}

func TestWithUntracedPathsSkipsSpanButStillRecords(t *testing.T) {
	sr := withRecorder(t)
	var got []RequestMetric

	h := HTTPMiddleware("test-server",
		WithUntracedPaths("/health"),
		WithRecorder(func(_ context.Context, m RequestMetric) { got = append(got, m) }),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trace.SpanContextFromContext(r.Context()).IsValid() {
			t.Error("untraced path rooted a span")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))

	if spans := sr.Ended(); len(spans) != 0 {
		t.Fatalf("ended spans = %d, want 0", len(spans))
	}
	if len(got) != 1 {
		t.Fatalf("recorded metrics = %d, want 1", len(got))
	}
	if got[0].Action != "GET /health" {
		t.Errorf("action = %q, want %q", got[0].Action, "GET /health")
	}
	if got[0].Outcome != "success" || got[0].StatusCode != http.StatusNoContent {
		t.Errorf("outcome/status = %q/%d, want success/204", got[0].Outcome, got[0].StatusCode)
	}
}

// TestWithUntracedPathsLeavesOtherPathsTraced keeps the skip path-scoped: an
// option meant for probes must not silently untrace the whole server.
func TestWithUntracedPathsLeavesOtherPathsTraced(t *testing.T) {
	sr := withRecorder(t)

	h := HTTPMiddleware("test-server", WithUntracedPaths("/health"))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/other", nil))

	if spans := sr.Ended(); len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
}

func TestWithRecorderReplacesTheMetricSink(t *testing.T) {
	withRecorder(t)
	var got []RequestMetric

	h := HTTPMiddleware("test-server",
		WithRecorder(func(_ context.Context, m RequestMetric) { got = append(got, m) }),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetRequestAction(r.Context(), "GetObject")
		SetRequestErrorCode(r.Context(), "NoSuchKey")
		w.WriteHeader(http.StatusNotFound)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/b/k", nil))

	if len(got) != 1 {
		t.Fatalf("recorded metrics = %d, want 1", len(got))
	}
	if got[0].Action != "GetObject" || got[0].ErrorCode != "NoSuchKey" {
		t.Errorf("action/error = %q/%q, want GetObject/NoSuchKey", got[0].Action, got[0].ErrorCode)
	}
	if got[0].Outcome != "client_error" {
		t.Errorf("outcome = %q, want client_error", got[0].Outcome)
	}
}

func TestHTTPMiddlewareExtractsTraceparent(t *testing.T) {
	sr := withRecorder(t)
	// Extraction needs the W3C propagator installed (Init does this even
	// without an endpoint).
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	if _, err := Init(t.Context(), "test-svc"); err != nil {
		t.Fatalf("Init: %v", err)
	}

	h := HTTPMiddleware("test-server")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/y", nil)
	req.Header.Set("Traceparent", "00-0102030405060708090a0b0c0d0e0f10-0a0b0c0d0e0f0102-01")
	h.ServeHTTP(httptest.NewRecorder(), req)

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	if got := spans[0].SpanContext().TraceID().String(); got != "0102030405060708090a0b0c0d0e0f10" {
		t.Errorf("trace id = %s, want inbound traceparent trace id", got)
	}
	if got := spans[0].Parent().SpanID().String(); got != "0a0b0c0d0e0f0102" {
		t.Errorf("parent span id = %s, want inbound span id", got)
	}
}
