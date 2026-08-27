// Package safecast holds range-checked integer conversions that clamp rather
// than wrap, so a value that does not fit the target type saturates at its
// bound instead of silently becoming a small or negative number.
package safecast

import "math"

// Int64ToUint64 converts int64 to uint64, returning 0 if negative.
func Int64ToUint64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// Int64ToUint32 converts int64 to uint32, returning 0 if negative and capping at math.MaxUint32.
func Int64ToUint32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// IntToUint8 converts int to uint8, clamping to [0, 255].
func IntToUint8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint8 {
		return math.MaxUint8
	}
	return uint8(v)
}

// IntToUint16 converts int to uint16, returning 0 if negative and capping at math.MaxUint16.
func IntToUint16(v int) uint16 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(v)
}

// IntToUint32 converts int to uint32, returning 0 if negative and capping at math.MaxUint32.
func IntToUint32(v int) uint32 {
	if v < 0 {
		return 0
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// IntToUint64 converts int to uint64, returning 0 if negative.
func IntToUint64(v int) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// Uint64ToInt converts uint64 to int, capping at math.MaxInt.
func Uint64ToInt(v uint64) int {
	if v > math.MaxInt {
		return math.MaxInt
	}
	return int(v)
}

// Uint64ToInt64 converts uint64 to int64, capping at math.MaxInt64.
func Uint64ToInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// Uint64ToUint32 converts uint64 to uint32, capping at math.MaxUint32.
func Uint64ToUint32(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}
