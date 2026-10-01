package iampolicy

import (
	"errors"
	"log/slog"
	"math"
	"strconv"
	"strings"
)

var errNotANumber = errors.New("not a decimal number")

// Number is an exact decimal: digits × 10^exp, with digits free of leading and
// trailing zeros, so equal values have one representation. Zero has no digits.
type Number struct {
	neg    bool
	digits string
	exp    int64
}

// ParseNumber reads a numeric condition value or a numeric request key the way
// AWS does: an optional sign, digits with an optional point, and an optional
// exponent, compared exactly rather than as a float. Write paths reject what fails.
func ParseNumber(s string) (Number, error) {
	var n Number
	if s != "" && (s[0] == '+' || s[0] == '-') {
		n.neg = s[0] == '-'
		s = s[1:]
	}
	mantissa, exponent, hasExp := strings.Cut(strings.ReplaceAll(s, "E", "e"), "e")
	whole, frac, _ := strings.Cut(mantissa, ".")
	mant := whole + frac
	if !allDigits(mant) {
		return Number{}, errNotANumber
	}
	var exp int64
	if hasExp {
		// AWS bounds the exponent to 32 bits too.
		e, err := strconv.ParseInt(exponent, 10, 32)
		if err != nil {
			return Number{}, errNotANumber
		}
		exp = e
	}
	// AWS holds the scale (fraction digits less the exponent) in 32 bits and
	// rejects a value whose scale overflows, so 1e-2147483648 is not a number.
	scale := int64(len(frac)) - exp
	if scale < math.MinInt32 || scale > math.MaxInt32 {
		return Number{}, errNotANumber
	}

	digits := strings.TrimLeft(mant, "0")
	trimmed := strings.TrimRight(digits, "0")
	if trimmed == "" {
		return Number{}, nil
	}
	n.digits = trimmed
	n.exp = int64(len(digits)-len(trimmed)) - scale
	return n, nil
}

// Compare returns -1, 0 or 1 as n is less than, equal to or greater than o.
func (n Number) Compare(o Number) int {
	if n.sign() != o.sign() {
		if n.sign() < o.sign() {
			return -1
		}
		return 1
	}
	if n.digits == "" {
		return 0
	}
	cmp := n.magnitudeCompare(o)
	if n.neg {
		return -cmp
	}
	return cmp
}

func (n Number) sign() int {
	switch {
	case n.digits == "":
		return 0
	case n.neg:
		return -1
	}
	return 1
}

// magnitudeCompare compares absolute values. The position of the leading digit
// decides first; at equal positions the digit strings compare lexically, since
// neither carries a trailing zero.
func (n Number) magnitudeCompare(o Number) int {
	nTop, oTop := int64(len(n.digits))+n.exp, int64(len(o.digits))+o.exp
	switch {
	case nTop < oTop:
		return -1
	case nTop > oTop:
		return 1
	}
	return strings.Compare(n.digits, o.digits)
}

// numericHoldsAny applies a positive numeric operator: actual compared against
// each value, ORed. Values are compared as written, policy variables having no
// meaning here. An unparseable request value takes failClosed, as a date does.
func numericHoldsAny(operator, actual string, values []string, failClosed bool) bool {
	at, err := ParseNumber(actual)
	if err != nil {
		slog.Warn("iampolicy: request value is not a number, so the condition cannot compare",
			"value", actual, "operator", operator, "matches", failClosed)
		return failClosed
	}
	for _, v := range values {
		want, err := ParseNumber(v)
		if err != nil {
			slog.Warn("iampolicy: numeric condition value is not a decimal number, matching nothing",
				"value", v, "operator", operator)
			continue
		}
		if numericCompares(operator, at.Compare(want)) {
			return true
		}
	}
	return false
}

// numericCompares reports whether cmp, the request value compared to the
// policy value, satisfies operator.
func numericCompares(operator string, cmp int) bool {
	switch operator {
	case OpNumericEquals:
		return cmp == 0
	case OpNumericLessThan:
		return cmp < 0
	case OpNumericLessThanEquals:
		return cmp <= 0
	case OpNumericGreaterThan:
		return cmp > 0
	case OpNumericGreaterThanEquals:
		return cmp >= 0
	}
	return false
}
