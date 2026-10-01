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
	OpStringEquals:              {"alice", []string{"alice"}},
	OpStringNotEquals:           {"alice", []string{"bob"}},
	OpStringEqualsIgnoreCase:    {"Alice", []string{"alice"}},
	OpStringNotEqualsIgnoreCase: {"Alice", []string{"bob"}},
	OpStringLike:                {"home/alice/report.txt", []string{"home/*"}},
	OpStringNotLike:             {"home/alice/report.txt", []string{"logs/*"}},
	OpIPAddress:                 {"10.4.1.9", []string{"10.0.0.0/8"}},
	OpNotIPAddress:              {"192.0.2.10", []string{"10.0.0.0/8"}},
	OpBool:                      {"true", []string{"true"}},
	OpArnEquals:                 {"arn:aws:iam::111122223333:role/ops", []string{"arn:aws:iam::111122223333:role/*"}},
	OpArnLike:                   {"arn:aws:iam::111122223333:role/ops", []string{"arn:aws:iam::*:role/ops"}},
	OpArnNotEquals:              {"arn:aws:iam::111122223333:role/ops", []string{"arn:aws:iam::444455556666:role/*"}},
	OpArnNotLike:                {"arn:aws:iam::111122223333:role/ops", []string{"arn:aws:s3:::*"}},
	OpDateEquals:                {"2026-10-01T12:00:00Z", []string{"1790856000"}},
	OpDateNotEquals:             {"2026-10-01T12:00:00Z", []string{"2026-10-01"}},
	OpDateLessThan:              {"2026-10-01T12:00:00Z", []string{"2027-01-01"}},
	OpDateLessThanEquals:        {"2026-10-01T12:00:00Z", []string{"2026-10-01T12:00Z"}},
	OpDateGreaterThan:           {"1790856000", []string{"2026-10"}},
	OpDateGreaterThanEquals:     {"1790856000", []string{"2026-10-01T14:00:00+02:00"}},
}

// Operators the matcher implements that no supported key can carry yet: none is
// ARN-valued. Each must be registered once an ARN key with a door exists, and
// removed from here then.
var implementedAwaitingKey = map[string]string{
	OpArnEquals:    "no supported key is ARN-valued; aws:SourceArn is blocked on a door",
	OpArnLike:      "no supported key is ARN-valued; aws:SourceArn is blocked on a door",
	OpArnNotEquals: "no supported key is ARN-valued; aws:SourceArn is blocked on a door",
	OpArnNotLike:   "no supported key is ARN-valued; aws:SourceArn is blocked on a door",
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
			assert.True(t, conditionHolds(op, sample.actual, sample.values, nil, false),
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
		reason, awaiting := implementedAwaitingKey[op]
		assert.Equal(t, !awaiting, advertised,
			"operator %q: either a key advertises it or implementedAwaitingKey says why none does (%q), "+
				"and it cannot be both or neither", op, reason)
	}
}

// Every negated operator inverts an operator the matcher implements, and is
// advertised on exactly the keys its positive form is.
func TestNegatedOperators_MirrorTheirPositiveForm(t *testing.T) {
	for negated, positive := range negatedOperators {
		_, ok := matcherSamples[positive]
		require.True(t, ok, "%q negates %q, which the matcher does not implement", negated, positive)
		for key := range supportedConditions {
			assert.Equal(t, SupportedCondition(positive, key), SupportedCondition(negated, key),
				"%q and its negation %q are advertised differently on %q", positive, negated, key)
		}
	}
}

// Every IfExists form is advertised on exactly the keys its base operator is,
// and Null on every registered key but never in an IfExists form.
func TestIfExistsAndNull_FollowTheRegistry(t *testing.T) {
	for key := range supportedConditions {
		for op := range matcherSamples {
			assert.Equal(t, SupportedCondition(op, key), SupportedCondition(op+IfExistsSuffix, key),
				"%q and %q are advertised differently on %q", op, op+IfExistsSuffix, key)
		}
		assert.True(t, SupportedCondition(OpNull, key), "Null is not advertised on registered key %q", key)
		assert.False(t, SupportedCondition(OpNull+IfExistsSuffix, key), "NullIfExists is advertised on %q", key)
		assert.False(t, SupportedCondition(IfExistsSuffix, key), "a bare IfExists is advertised on %q", key)
		assert.False(t, SupportedCondition(OpStringEquals+IfExistsSuffix+IfExistsSuffix, key),
			"a doubled suffix is advertised on %q", key)
	}
}

func TestMatchARN(t *testing.T) {
	const role = "arn:aws:iam::111122223333:role/ops"
	tests := []struct {
		name    string
		pattern string
		value   string
		keys    ConditionKeys
		want    bool
	}{
		{"exact", role, role, nil, true},
		{"account wildcard", "arn:aws:iam::*:role/ops", role, nil, true},
		{"single-character wildcard", "arn:aws:iam::11112222333?:role/ops", role, nil, true},
		{"case-sensitive", "arn:aws:iam::111122223333:role/Ops", role, nil, false},
		// A whole-string glob would let one * span service, region and account.
		{"wildcard does not cross a colon", "arn:aws:*:role/ops", role, nil, false},
		{"wildcard confined to its component", "arn:aws:iam:*:role/ops", role, nil, false},
		{"empty component matches only empty", "arn:aws:iam:x:111122223333:role/ops", role, nil, false},
		// The resource component runs to the end, so it may carry colons.
		{"resource component spans colons", "arn:aws:logs:us-east-1:111122223333:log-group:*",
			"arn:aws:logs:us-east-1:111122223333:log-group:app:log-stream:x", nil, true},
		{"pattern is not an ARN", "arn:aws:iam", role, nil, false},
		{"variable resolves", "arn:aws:iam::${aws:PrincipalAccount}:role/ops", role,
			ConditionKeys{KeyPrincipalAccount: "111122223333"}, true},
		{"variable resolves to another value", "arn:aws:iam::${aws:PrincipalAccount}:role/ops", role,
			ConditionKeys{KeyPrincipalAccount: "444455556666"}, false},
		// A role session's ID carries a colon; it must not shift a component.
		{"colon-bearing variable stays in its component", "arn:aws:s3:::home/${aws:userid}/*",
			"arn:aws:s3:::home/AROAOPS:deploy/x", ConditionKeys{KeyUserID: "AROAOPS:deploy"}, true},
		// Substituting before splitting would let the value's colon line up
		// with the account and resource boundary and match.
		{"colon-bearing variable does not shift a boundary", "arn:aws:iam::${aws:userid}:role/x",
			"arn:aws:iam::111:222:role/x", ConditionKeys{KeyUserID: "111:222"}, false},
		{"substituted wildcard is literal", "arn:aws:s3:::home/${aws:username}",
			"arn:aws:s3:::home/alice", ConditionKeys{KeyUsername: "*"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, conditionHolds(OpArnLike, tt.value, []string{tt.pattern}, tt.keys, false))
			assert.Equal(t, tt.want, conditionHolds(OpArnEquals, tt.value, []string{tt.pattern}, tt.keys, false))
			assert.Equal(t, !tt.want, conditionHolds(OpArnNotLike, tt.value, []string{tt.pattern}, tt.keys, false))
			assert.Equal(t, !tt.want, conditionHolds(OpArnNotEquals, tt.value, []string{tt.pattern}, tt.keys, false))
		})
	}
}

// An unresolvable variable under an Arn operator only narrows access, before and
// after negation: an Allow does not fire and a Deny does.
func TestMatchARN_UnresolvableVariableFailsClosed(t *testing.T) {
	const role = "arn:aws:iam::111122223333:role/ops"
	pattern := []string{"arn:aws:iam::111122223333:role/${aws:username}"}
	for _, op := range []string{OpArnLike, OpArnNotLike} {
		assert.False(t, conditionHolds(op, role, pattern, nil, false), "%s in an Allow", op)
		assert.True(t, conditionHolds(op, role, pattern, nil, true), "%s in a Deny", op)
	}
}

// A request value that is not an ARN is input the matcher cannot compare, so
// it narrows access before and after negation, as an unparseable address does.
func TestMatchARN_NonARNValueFailsClosed(t *testing.T) {
	pattern := []string{"arn:aws:iam::*:role/*"}
	for _, op := range []string{OpArnLike, OpArnNotLike} {
		assert.False(t, conditionHolds(op, "ops", pattern, nil, false), "%s in an Allow", op)
		assert.True(t, conditionHolds(op, "ops", pattern, nil, true), "%s in a Deny", op)
	}
}
