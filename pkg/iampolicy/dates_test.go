package iampolicy_test

import (
	"testing"
	"time"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDate(t *testing.T) {
	utc := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339Nano, s)
		require.NoError(t, err)
		return v
	}
	accepted := []struct {
		value string
		want  time.Time
	}{
		{"2026-10", utc("2026-10-01T00:00:00Z")},
		{"2026-10-01", utc("2026-10-01T00:00:00Z")},
		{"2026-10-01T12:30Z", utc("2026-10-01T12:30:00Z")},
		{"2026-10-01T12:30+02:00", utc("2026-10-01T10:30:00Z")},
		{"2026-10-01T12:30:45Z", utc("2026-10-01T12:30:45Z")},
		{"2026-10-01T12:30:45-05:00", utc("2026-10-01T17:30:45Z")},
		{"2026-10-01T12:30:45.25Z", utc("2026-10-01T12:30:45.25Z")},
		{"1790856000", utc("2026-10-01T12:00:00Z")},
		{"0", utc("1970-01-01T00:00:00Z")},
		// AWS reads four digits as epoch seconds, not the W3C bare year.
		{"2020", utc("1970-01-01T00:33:40Z")},
		{"-100", utc("1969-12-31T23:58:20Z")},
	}
	for _, tt := range accepted {
		t.Run(tt.value, func(t *testing.T) {
			got, err := iampolicy.ParseDate(tt.value)
			require.NoError(t, err)
			assert.True(t, tt.want.Equal(got), "got %s, want %s", got, tt.want)
		})
	}

	rejected := []string{
		"", "today", "2026-1-5", "2026-10-01T12Z", "2026-10-01T12:30",
		"2026-10-01T12:30:45", "2026-10-01 12:30:45Z", "2026-13-01",
		"-", "--100", "1790856000.5", "99999999999999999999",
		"${aws:CurrentTime}", "Thu, 01 Oct 2026 12:00:00 GMT",
	}
	for _, v := range rejected {
		t.Run("rejects "+v, func(t *testing.T) {
			_, err := iampolicy.ParseDate(v)
			assert.Error(t, err)
		})
	}
}

// Both keys are written from one instant, each in a form ParseDate reads back
// to that instant at whole-second precision.
func TestSetRequestTime(t *testing.T) {
	now := time.Date(2026, 10, 1, 22, 0, 0, 750_000_000, time.FixedZone("AEST", 10*3600))
	keys := iampolicy.ConditionKeys{}
	keys.SetRequestTime(now)

	assert.Equal(t, "2026-10-01T12:00:00Z", keys[iampolicy.KeyCurrentTime])
	assert.Equal(t, "1790856000", keys[iampolicy.KeyEpochTime])
	for _, key := range []string{iampolicy.KeyCurrentTime, iampolicy.KeyEpochTime} {
		got, err := iampolicy.ParseDate(keys[key])
		require.NoError(t, err, key)
		assert.True(t, now.Truncate(time.Second).Equal(got), "%s reads back as %s", key, got)
	}
}
