package iampolicy

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// dateLayouts are the W3C ISO 8601 forms AWS documents, bar the bare year, which
// AWS reads as epoch seconds. Go accepts fractional seconds after the seconds
// field even though the layout does not spell them, covering ss.sTZD.
var dateLayouts = []string{
	"2006-01",
	"2006-01-02",
	"2006-01-02T15:04Z07:00",
	time.RFC3339,
}

// currentTimeLayout is how the doors spell aws:CurrentTime: UTC, whole seconds.
const currentTimeLayout = "2006-01-02T15:04:05Z"

// 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z in epoch seconds.
const (
	minEpochSeconds = -62135596800
	maxEpochSeconds = 253402300799
)

var errNotADate = errors.New("not an ISO 8601 date or epoch seconds")

// ParseDate reads a date condition value or a date-valued request key: one of
// the W3C ISO 8601 forms, or epoch seconds. As in AWS, any run of digits is epoch
// seconds, four included, and may be negative. Write paths reject what fails.
func ParseDate(s string) (time.Time, error) {
	if allDigits(strings.TrimPrefix(s, "-")) {
		secs, err := strconv.ParseInt(s, 10, 64)
		// time.Unix wraps near the int64 limits, so bound epoch seconds to the
		// years the ISO 8601 forms can spell.
		if err != nil || secs < minEpochSeconds || secs > maxEpochSeconds {
			return time.Time{}, errNotADate
		}
		return time.Unix(secs, 0).UTC(), nil
	}
	// Go reads a comma before fractional seconds; AWS documents only the period.
	if strings.Contains(s, ",") {
		return time.Time{}, errNotADate
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errNotADate
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// SetRequestTime writes aws:CurrentTime and aws:EpochTime from one instant, so
// every door spells both the same way. Doors pass the server clock.
func (k ConditionKeys) SetRequestTime(now time.Time) {
	k[KeyCurrentTime] = now.UTC().Format(currentTimeLayout)
	k[KeyEpochTime] = strconv.FormatInt(now.Unix(), 10)
}

// dateHoldsAny applies a positive date operator: actual compared against each
// value, ORed. Values are compared as written, policy variables having no
// meaning here. An unparseable request value takes failClosed, as an address does.
func dateHoldsAny(operator, actual string, values []string, failClosed bool) bool {
	at, err := ParseDate(actual)
	if err != nil {
		slog.Warn("iampolicy: request value is not a date, so the condition cannot compare",
			"value", actual, "operator", operator, "matches", failClosed)
		return failClosed
	}
	for _, v := range values {
		want, err := ParseDate(v)
		if err != nil {
			slog.Warn("iampolicy: date condition value is not an ISO 8601 date or epoch seconds, matching nothing",
				"value", v, "operator", operator)
			continue
		}
		if dateCompares(operator, at.Compare(want)) {
			return true
		}
	}
	return false
}

// dateCompares reports whether cmp, the request time compared to the policy
// value, satisfies operator.
func dateCompares(operator string, cmp int) bool {
	switch operator {
	case OpDateEquals:
		return cmp == 0
	case OpDateLessThan:
		return cmp < 0
	case OpDateLessThanEquals:
		return cmp <= 0
	case OpDateGreaterThan:
		return cmp > 0
	case OpDateGreaterThanEquals:
		return cmp >= 0
	}
	return false
}
