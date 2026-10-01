package iampolicy_test

import (
	"testing"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The accepted and rejected forms are the ones AWS's evaluator reads and
// Access Analyzer flags as TYPE_MISMATCH_NUMBER respectively.
func TestParseNumber(t *testing.T) {
	accepted := []string{
		"0", "10", "-5", "+10", "010", "10.5", "10.", ".5", "1e1", "1E1", "1e+1", "1e-1",
		"1.5e3", "99999999999999999999", "1e400", "1e2147483647", "1e-2147483647",
	}
	for _, v := range accepted {
		t.Run(v, func(t *testing.T) {
			_, err := iampolicy.ParseNumber(v)
			assert.NoError(t, err)
		})
	}

	rejected := []string{
		"", "+", "-", ".", "e1", "1e", "1e+", "abc", " 10", "10 ", "0x0A", "1_0", "10d", "10f", "10L",
		"--5", "+-5", "1e1.5", "1e1e1", "1.2.3", "NaN", "Infinity", "-Infinity", "1/2", "${aws:EpochTime}",
		// AWS holds the exponent and the scale in 32 bits.
		"1e2147483648", "1e-2147483648", "1e-2147483649", "1e99999999999",
	}
	for _, v := range rejected {
		t.Run("rejects "+v, func(t *testing.T) {
			_, err := iampolicy.ParseNumber(v)
			assert.Error(t, err)
		})
	}
}

func TestNumber_Compare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"10", "10.0", 0},
		{"10", "1e1", 0},
		{"010", "+10", 0},
		{"0.5", ".5", 0},
		{"-0", "0", 0},
		{"0", "0.000", 0},
		{"100", "1.00e2", 0},
		{"10", "10.5", -1},
		{"-10", "-10.5", 1},
		{"-1", "0", -1},
		{"0", "-1", 1},
		{"0.12", "0.123", -1},
		{"0.13", "0.123", 1},
		{"999", "1000", -1},
		{"1e400", "10", 1},
		{"1e-400", "0", 1},
		// Exact, not float64: these differ past the 53-bit mantissa.
		{"9007199254740993", "9007199254740992", 1},
		{"0.1", "0.10000000000000001", -1},
	}
	for _, tt := range tests {
		t.Run(tt.a+" vs "+tt.b, func(t *testing.T) {
			a, err := iampolicy.ParseNumber(tt.a)
			require.NoError(t, err)
			b, err := iampolicy.ParseNumber(tt.b)
			require.NoError(t, err)
			assert.Equal(t, tt.want, a.Compare(b))
			assert.Equal(t, -tt.want, b.Compare(a))
		})
	}
}
