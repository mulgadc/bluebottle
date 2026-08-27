package safecast_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mulgadc/bluebottle/pkg/safecast"
)

// Each wrapper has one or two clamp branches; tests cover the no-branch
// happy path and each branch. Boundary tests against MaxInt64/MaxUint8 etc.
// only exercise stdlib casts, so they are intentionally omitted.

func TestInt64ToUint64(t *testing.T) {
	tests := []struct {
		name string
		in   int64
		want uint64
	}{
		{"positive passes through", 42, 42},
		{"negative clamps to 0", -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.Int64ToUint64(tt.in))
		})
	}
}

func TestInt64ToUint32(t *testing.T) {
	tests := []struct {
		name string
		in   int64
		want uint32
	}{
		{"in range passes through", 42, 42},
		{"above max clamps", math.MaxUint32 + 1, math.MaxUint32},
		{"negative clamps to 0", -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.Int64ToUint32(tt.in))
		})
	}
}

func TestIntToUint8(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want uint8
	}{
		{"in range passes through", 128, 128},
		{"above max clamps", math.MaxUint8 + 1, math.MaxUint8},
		{"negative clamps to 0", -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.IntToUint8(tt.in))
		})
	}
}

func TestIntToUint16(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want uint16
	}{
		{"in range passes through", 4096, 4096},
		{"above max clamps", math.MaxUint16 + 1, math.MaxUint16},
		{"negative clamps to 0", -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.IntToUint16(tt.in))
		})
	}
}

func TestIntToUint32(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want uint32
	}{
		{"in range passes through", 42, 42},
		{"above max clamps", math.MaxUint32 + 1, math.MaxUint32},
		{"negative clamps to 0", -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.IntToUint32(tt.in))
		})
	}
}

func TestIntToUint64(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want uint64
	}{
		{"positive passes through", 42, 42},
		{"negative clamps to 0", -1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.IntToUint64(tt.in))
		})
	}
}

func TestUint64ToInt(t *testing.T) {
	tests := []struct {
		name string
		in   uint64
		want int
	}{
		{"in range passes through", 42, 42},
		{"above MaxInt clamps", uint64(math.MaxInt) + 1, math.MaxInt},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.Uint64ToInt(tt.in))
		})
	}
}

func TestUint64ToInt64(t *testing.T) {
	tests := []struct {
		name string
		in   uint64
		want int64
	}{
		{"in range passes through", 42, 42},
		{"above MaxInt64 clamps", uint64(math.MaxInt64) + 1, math.MaxInt64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.Uint64ToInt64(tt.in))
		})
	}
}

func TestUint64ToUint32(t *testing.T) {
	tests := []struct {
		name string
		in   uint64
		want uint32
	}{
		{"in range passes through", 42, 42},
		{"above MaxUint32 clamps", uint64(math.MaxUint32) + 1, math.MaxUint32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, safecast.Uint64ToUint32(tt.in))
		})
	}
}
