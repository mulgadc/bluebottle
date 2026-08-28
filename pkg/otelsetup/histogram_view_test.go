package otelsetup

import (
	"context"
	"slices"
	"testing"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newViewTestProvider builds a MeterProvider carrying secondsHistogramView
// over a ManualReader, independent of the process-global provider Init
// installs, so these tests can collect data points without racing other
// tests over the OTel globals.
func newViewTestProvider(t *testing.T) (*sdkmetric.ManualReader, metric.Meter) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(reader),
		sdkmetric.WithView(secondsHistogramView()),
	)
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	return reader, mp.Meter("otelsetup_test")
}

// collectHistogram gathers one Collect and returns the named metric's
// histogram data, failing the test if it is missing or the wrong shape.
func collectHistogram(t *testing.T, reader *sdkmetric.ManualReader, name string) metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m
			}
		}
	}
	t.Fatalf("metric %s not collected", name)
	return metricdata.Metrics{}
}

func TestSecondsHistogramViewAppliesFleetBoundaries(t *testing.T) {
	reader, meter := newViewTestProvider(t)
	hist, err := meter.Float64Histogram("test.seconds.duration",
		metric.WithUnit("s"), metric.WithDescription("test histogram"))
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}

	ctx := context.Background()
	hist.Record(ctx, 0.01)
	hist.Record(ctx, 0.2)

	m := collectHistogram(t, reader, "test.seconds.duration")
	data, ok := m.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("Data is %T, want Histogram[float64]", m.Data)
	}
	for _, dp := range data.DataPoints {
		if !slices.Equal(dp.Bounds, secondsHistogramBoundaries) {
			t.Errorf("Bounds = %v, want %v", dp.Bounds, secondsHistogramBoundaries)
		}
	}
}

// TestSecondsHistogramViewSeparatesSubSecondValues is the regression the bug
// report describes: with the SDK default (millisecond-scale) boundaries,
// every value below 5 shares the first bucket and a percentile aggregation
// reads back as that bucket's centroid regardless of the real distribution.
// Asserting the Bounds slice alone would not catch a future change that kept
// the right bounds but broke instrument selection, so this also checks the
// samples actually spread across more than one bucket.
func TestSecondsHistogramViewSeparatesSubSecondValues(t *testing.T) {
	reader, meter := newViewTestProvider(t)
	hist, err := meter.Float64Histogram("test.seconds.spread", metric.WithUnit("s"))
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}

	ctx := context.Background()
	for _, v := range []float64{0.001, 0.005, 0.01, 0.05, 0.1} {
		hist.Record(ctx, v)
	}

	m := collectHistogram(t, reader, "test.seconds.spread")
	data, ok := m.Data.(metricdata.Histogram[float64])
	if !ok {
		t.Fatalf("Data is %T, want Histogram[float64]", m.Data)
	}
	if len(data.DataPoints) != 1 {
		t.Fatalf("data points = %d, want 1", len(data.DataPoints))
	}
	dp := data.DataPoints[0]

	occupied := 0
	for _, c := range dp.BucketCounts {
		if c > 0 {
			occupied++
		}
	}
	if occupied < 2 {
		t.Errorf("1ms-100ms samples occupied %d bucket(s), want more than 1 (bucket counts: %v, bounds: %v)",
			occupied, dp.BucketCounts, dp.Bounds)
	}
}

func TestSecondsHistogramViewLeavesOtherUnitsAlone(t *testing.T) {
	reader, meter := newViewTestProvider(t)
	hist, err := meter.Int64Histogram("test.bytes.size", metric.WithUnit("By"))
	if err != nil {
		t.Fatalf("Int64Histogram: %v", err)
	}

	hist.Record(context.Background(), 4096)

	m := collectHistogram(t, reader, "test.bytes.size")
	data, ok := m.Data.(metricdata.Histogram[int64])
	if !ok {
		t.Fatalf("Data is %T, want Histogram[int64]", m.Data)
	}

	wantAgg := sdkmetric.DefaultAggregationSelector(sdkmetric.InstrumentKindHistogram)
	wantBounds := wantAgg.(sdkmetric.AggregationExplicitBucketHistogram).Boundaries
	for _, dp := range data.DataPoints {
		if slices.Equal(dp.Bounds, secondsHistogramBoundaries) {
			t.Errorf("By-unit histogram picked up the seconds view boundaries: %v", dp.Bounds)
		}
		if !slices.Equal(dp.Bounds, wantBounds) {
			t.Errorf("Bounds = %v, want SDK default %v", dp.Bounds, wantBounds)
		}
	}
}

func TestSecondsHistogramViewKeepsInstrumentNameAndDescription(t *testing.T) {
	reader, meter := newViewTestProvider(t)
	const wantDesc = "duration of the widget frobnication pipeline"
	hist, err := meter.Float64Histogram("test.widget.frob.duration",
		metric.WithUnit("s"), metric.WithDescription(wantDesc))
	if err != nil {
		t.Fatalf("Float64Histogram: %v", err)
	}

	hist.Record(context.Background(), 0.05)

	m := collectHistogram(t, reader, "test.widget.frob.duration")
	if m.Name != "test.widget.frob.duration" {
		t.Errorf("Name = %q, want test.widget.frob.duration", m.Name)
	}
	if m.Description != wantDesc {
		t.Errorf("Description = %q, want %q", m.Description, wantDesc)
	}
}
