package otelsetup

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const httpTracerName = "github.com/mulgadc/bluebottle/pkg/otelsetup"

// statusRecorder captures the response status and body size for span and
// metric attributes.
type statusRecorder struct {
	http.ResponseWriter

	status  int
	written int64
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Write tracks bytes actually written to the client, not a forced read of
// the response body.
func (w *statusRecorder) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

// Unwrap returns the wrapped ResponseWriter, letting http.ResponseController
// (and any other Unwrap-aware caller) walk past statusRecorder to reach the
// real writer underneath.
func (w *statusRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Flush implements http.Flusher by delegating to the wrapped ResponseWriter.
// Without this, statusRecorder blocks every downstream Flush call from ever
// reaching the real writer: the call succeeds as a no-op but no bytes reach
// the socket, silently breaking streaming handlers.
func (w *statusRecorder) Flush() {
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Hijack implements http.Hijacker so websocket and CONNECT upgrades survive
// the wrapper. Bytes written to the raw connection are outside the span's
// accounting.
func (w *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

// ReadFrom implements io.ReaderFrom so writers offering a sendfile fast path
// keep it, and still counts the bytes. Falls back to a plain copy when the
// wrapped writer has no ReadFrom of its own.
func (w *statusRecorder) ReadFrom(r io.Reader) (int64, error) {
	var n int64
	var err error
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
	} else {
		n, err = io.Copy(w.ResponseWriter, r)
	}
	w.written += n
	return n, err
}

// HTTPMiddleware opens a server span per request, honoring an inbound W3C
// traceparent header, and records request count/duration metrics. Handlers
// rename the span (and SetRequestAction) once they resolve a logical
// operation (e.g. the S3 action). No-op unless Init configured export.
func HTTPMiddleware(serverName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			action := &requestAction{name: r.Method}
			ctx = context.WithValue(ctx, requestActionKey{}, action)
			ctx, span := otel.Tracer(httpTracerName).Start(ctx, r.Method+" "+r.URL.Path,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					semconv.HTTPRequestMethodKey.String(r.Method),
					semconv.URLPath(r.URL.Path),
					attribute.String("server.name", serverName),
				))
			defer span.End()

			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r.WithContext(ctx))

			span.SetAttributes(semconv.HTTPResponseStatusCode(rec.status))
			outcome := "success"
			if rec.status >= http.StatusInternalServerError {
				span.SetStatus(codes.Error, fmt.Sprintf("HTTP %d", rec.status))
				outcome = "error"
			}

			// Content-Length is read from the header set before the body was
			// consumed; -1 (unknown/chunked) is left unrecorded rather than
			// forcing a body read to measure it.
			reqBytes := max(r.ContentLength, 0)
			RecordRequest(ctx, RequestMetric{
				Action:     action.name,
				Outcome:    outcome,
				StatusCode: rec.status,
				ErrorCode:  action.errorCode,
				ReqBytes:   reqBytes,
				RespBytes:  rec.written,
				Elapsed:    time.Since(start),
			})
		})
	}
}
