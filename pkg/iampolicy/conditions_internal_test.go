package iampolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// matcherSamples pairs each implemented operator with an input it must match.
// Adding an operator to supportedConditions without a matcher case fails here,
// which is the whole point of the write-path allowlist gating on that table.
var matcherSamples = map[string]struct {
	actual string
	values []string
}{
	OpStringEquals: {"alice", []string{"alice"}},
	OpStringLike:   {"home/alice/report.txt", []string{"home/*"}},
	OpIPAddress:    {"10.4.1.9", []string{"10.0.0.0/8"}},
	OpBool:         {"true", []string{"true"}},
}

// Iterates the allowlist itself rather than a hardcoded copy of it: a table
// entry the matcher does not implement would be accepted at the front door and
// then compare false forever, minting a grant that silently never fires.
func TestSupportedConditions_EveryAdvertisedOperatorIsImplemented(t *testing.T) {
	for key, ops := range supportedConditions {
		for op, advertised := range ops {
			if !advertised {
				continue
			}
			sample, ok := matcherSamples[op]
			require.True(t, ok, "operator %q advertised on key %q has no matcher sample", op, key)
			assert.True(t, conditionHolds(op, sample.actual, sample.values, nil),
				"operator %q advertised on key %q but conditionHolds never matches", op, key)
		}
	}
}

// The mirror direction: an operator the matcher implements but the table never
// advertises is unreachable, because the validator rejects it at write time.
func TestSupportedConditions_EveryImplementedOperatorIsAdvertised(t *testing.T) {
	for op := range matcherSamples {
		advertised := false
		for key := range supportedConditions {
			if SupportedCondition(op, key) {
				advertised = true
				break
			}
		}
		assert.True(t, advertised, "operator %q is implemented but advertised on no key", op)
	}
}
