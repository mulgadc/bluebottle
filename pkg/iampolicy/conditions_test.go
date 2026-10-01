package iampolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionValue_LenientLeaves(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want iampolicy.ConditionValue
	}{
		{"string", `"true"`, iampolicy.ConditionValue{"true"}},
		{"bool", `true`, iampolicy.ConditionValue{"true"}},
		{"number", `10`, iampolicy.ConditionValue{"10"}},
		{"array", `["a","b"]`, iampolicy.ConditionValue{"a", "b"}},
		{"null", `null`, nil},
		{"mixed array", `[true,10,"a"]`, iampolicy.ConditionValue{"true", "10", "a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got iampolicy.ConditionValue
			require.NoError(t, json.Unmarshal([]byte(tt.in), &got))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConditionValue_RejectsObject(t *testing.T) {
	var got iampolicy.ConditionValue
	assert.Error(t, json.Unmarshal([]byte(`{"nested":1}`), &got))
}

func TestConditionValue_MarshalsStringForm(t *testing.T) {
	out, err := json.Marshal(iampolicy.ConditionValue{"true"})
	require.NoError(t, err)
	assert.JSONEq(t, `"true"`, string(out))

	out, err = json.Marshal(iampolicy.ConditionValue{"a", "b"})
	require.NoError(t, err)
	assert.JSONEq(t, `["a","b"]`, string(out))
}

// A Bool condition on aws:SecureTransport is a shape AWS emits routinely; it
// must load rather than failing the whole document.
func TestStatement_BoolConditionParses(t *testing.T) {
	const src = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*",
	 "Condition":{"Bool":{"aws:SecureTransport":true}}}]}`
	var d iampolicy.PolicyDocument
	require.NoError(t, json.Unmarshal([]byte(src), &d))
	assert.Equal(t, iampolicy.ConditionValue{"true"},
		d.Statement[0].Condition["Bool"]["aws:SecureTransport"])
}

func TestStatement_RetainsConditionOnRoundTrip(t *testing.T) {
	const src = `{"Version":"2012-10-17","Statement":[{"Sid":"OfficeOnly","Effect":"Allow","Action":"*","Resource":"*",
	 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`
	var d iampolicy.PolicyDocument
	require.NoError(t, json.Unmarshal([]byte(src), &d))

	out, err := json.Marshal(d)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"Condition"`)
	assert.Contains(t, string(out), `"aws:SourceIp":"10.0.0.0/8"`)
}

func TestStatement_RetainsNotActionAndNotResource(t *testing.T) {
	const src = `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","NotAction":"sts:AssumeRole",
	 "NotResource":["arn:aws:s3:::public/*"],"Resource":"*","Principal":"*"}]}`
	var d iampolicy.PolicyDocument
	require.NoError(t, json.Unmarshal([]byte(src), &d))

	assert.Equal(t, iampolicy.StringOrArr{"sts:AssumeRole"}, d.Statement[0].NotAction)
	assert.Equal(t, iampolicy.StringOrArr{"arn:aws:s3:::public/*"}, d.Statement[0].NotResource)
	assert.JSONEq(t, `"*"`, string(d.Statement[0].Principal))
}

func TestSupportedCondition(t *testing.T) {
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpIPAddress, iampolicy.KeySourceIP))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpStringLike, iampolicy.KeyS3Prefix))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpBool, iampolicy.KeySecureTransport))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpStringEquals, iampolicy.KeyUsername))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpStringEquals, iampolicy.KeyPrincipalAccount))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpStringEquals, iampolicy.KeyUserID))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpStringLike, iampolicy.KeyUserID))

	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpNotIPAddress, iampolicy.KeySourceIP))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpStringNotEquals, iampolicy.KeyUsername))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpStringNotLike, iampolicy.KeyUserID))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpStringEqualsIgnoreCase, iampolicy.KeyPrincipalType))

	// Right key, wrong operator.
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpStringEquals, iampolicy.KeySourceIP))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpStringNotEquals, iampolicy.KeySourceIP))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpNotIPAddress, iampolicy.KeyUsername))
	// StringNotLike follows StringLike, which aws:username does not carry.
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpStringNotLike, iampolicy.KeyUsername))
	// No supported key is ARN-valued.
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpArnLike, iampolicy.KeyUserID))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpIPAddress, iampolicy.KeyUsername))
	// MFA is hard-dropped: spinifex has no MFA, so the key could never be true.
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpBool, "aws:MultiFactorAuthPresent"))
	// The date family is on the two date-valued keys and nowhere else.
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpDateGreaterThan, iampolicy.KeyCurrentTime))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpDateNotEquals, iampolicy.KeyEpochTime))
	assert.True(t, iampolicy.SupportedCondition("DateLessThanIfExists", iampolicy.KeyCurrentTime))
	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpNull, iampolicy.KeyEpochTime))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpDateGreaterThan, iampolicy.KeyUsername))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpStringEquals, iampolicy.KeyCurrentTime))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpDateLessThan, "aws:TokenIssueTime"))

	assert.True(t, iampolicy.SupportedCondition(iampolicy.OpNull, iampolicy.KeyS3Prefix))
	assert.True(t, iampolicy.SupportedCondition("StringLikeIfExists", iampolicy.KeyUserID))
	assert.True(t, iampolicy.SupportedCondition("NotIpAddressIfExists", iampolicy.KeySourceIP))
	assert.False(t, iampolicy.SupportedCondition("StringLikeIfExists", iampolicy.KeyUsername))
	assert.False(t, iampolicy.SupportedCondition("NullIfExists", iampolicy.KeyUsername))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpNull, "aws:MultiFactorAuthPresent"))
}

// condDoc builds a single-statement Allow carrying one condition.
func condDoc(operator, key string, values ...string) iampolicy.PolicyDocument {
	return iampolicy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []iampolicy.Statement{{
			Sid:      "Conditioned",
			Effect:   iampolicy.EffectAllow,
			Action:   iampolicy.StringOrArr{"s3:*"},
			Resource: iampolicy.StringOrArr{"*"},
			Condition: map[string]map[string]iampolicy.ConditionValue{
				operator: {key: values},
			},
		}},
	}
}

func TestEvaluateWithKeys_Operators(t *testing.T) {
	tests := []struct {
		name     string
		operator string
		key      string
		values   []string
		keys     iampolicy.ConditionKeys
		want     iampolicy.Decision
	}{
		{"IpAddress in CIDR", iampolicy.OpIPAddress, iampolicy.KeySourceIP,
			[]string{"10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "10.4.1.9"}, iampolicy.Allow},
		{"IpAddress outside CIDR", iampolicy.OpIPAddress, iampolicy.KeySourceIP,
			[]string{"10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "192.168.1.1"}, iampolicy.Deny},
		{"IpAddress exact address", iampolicy.OpIPAddress, iampolicy.KeySourceIP,
			[]string{"203.0.113.7"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "203.0.113.7"}, iampolicy.Allow},
		{"IpAddress v4-mapped v6 caller", iampolicy.OpIPAddress, iampolicy.KeySourceIP,
			[]string{"10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "::ffff:10.4.1.9"}, iampolicy.Allow},
		{"IpAddress unparseable caller", iampolicy.OpIPAddress, iampolicy.KeySourceIP,
			[]string{"10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "not-an-ip"}, iampolicy.Deny},
		{"IpAddress any of several", iampolicy.OpIPAddress, iampolicy.KeySourceIP,
			[]string{"172.16.0.0/12", "10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "10.4.1.9"}, iampolicy.Allow},

		{"StringEquals match", iampolicy.OpStringEquals, iampolicy.KeyUsername,
			[]string{"alice"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Allow},
		{"StringEquals mismatch", iampolicy.OpStringEquals, iampolicy.KeyUsername,
			[]string{"alice"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "bob"}, iampolicy.Deny},
		{"StringEquals is case-sensitive", iampolicy.OpStringEquals, iampolicy.KeyUsername,
			[]string{"alice"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "Alice"}, iampolicy.Deny},
		{"StringEquals account", iampolicy.OpStringEquals, iampolicy.KeyPrincipalAccount,
			[]string{"123456789012"}, iampolicy.ConditionKeys{iampolicy.KeyPrincipalAccount: "123456789012"}, iampolicy.Allow},
		{"StringEquals user ID", iampolicy.OpStringEquals, iampolicy.KeyUserID,
			[]string{"AIDAALICE"}, iampolicy.ConditionKeys{iampolicy.KeyUserID: "AIDAALICE"}, iampolicy.Allow},
		{"StringEquals user ID mismatch", iampolicy.OpStringEquals, iampolicy.KeyUserID,
			[]string{"AIDAALICE"}, iampolicy.ConditionKeys{iampolicy.KeyUserID: "AIDABOB"}, iampolicy.Deny},
		// A session's ID is the role ID and the session name, so a wildcard on
		// the second half pins every session of one role and no other role.
		{"StringLike any session of one role", iampolicy.OpStringLike, iampolicy.KeyUserID,
			[]string{"AROASHAREDOPS:*"}, iampolicy.ConditionKeys{iampolicy.KeyUserID: "AROASHAREDOPS:deploy"}, iampolicy.Allow},
		{"StringLike does not span roles", iampolicy.OpStringLike, iampolicy.KeyUserID,
			[]string{"AROASHAREDOPS:*"}, iampolicy.ConditionKeys{iampolicy.KeyUserID: "AROAOTHER:deploy"}, iampolicy.Deny},

		{"StringLike wildcard match", iampolicy.OpStringLike, iampolicy.KeyS3Prefix,
			[]string{"home/alice/*"}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/alice/docs/"}, iampolicy.Allow},
		{"StringLike wildcard mismatch", iampolicy.OpStringLike, iampolicy.KeyS3Prefix,
			[]string{"home/alice/*"}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/bob/"}, iampolicy.Deny},
		{"StringLike single-character match", iampolicy.OpStringLike, iampolicy.KeyS3Prefix,
			[]string{"home/alice?/"}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/alice1/"}, iampolicy.Allow},
		{"StringLike single-character mismatch", iampolicy.OpStringLike, iampolicy.KeyS3Prefix,
			[]string{"home/alice?/"}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/alice/"}, iampolicy.Deny},
		{"StringEquals prefix exact", iampolicy.OpStringEquals, iampolicy.KeyS3Prefix,
			[]string{"logs/"}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "logs/"}, iampolicy.Allow},

		{"Bool true", iampolicy.OpBool, iampolicy.KeySecureTransport,
			[]string{"true"}, iampolicy.ConditionKeys{iampolicy.KeySecureTransport: "true"}, iampolicy.Allow},
		{"Bool mismatch", iampolicy.OpBool, iampolicy.KeySecureTransport,
			[]string{"true"}, iampolicy.ConditionKeys{iampolicy.KeySecureTransport: "false"}, iampolicy.Deny},
		{"Bool ignores case", iampolicy.OpBool, iampolicy.KeySecureTransport,
			[]string{"True"}, iampolicy.ConditionKeys{iampolicy.KeySecureTransport: "true"}, iampolicy.Allow},

		// An absent key evaluates the condition false, so a policy written for
		// one data plane's keys simply does not fire on another's.
		{"absent key", iampolicy.OpStringLike, iampolicy.KeyS3Prefix,
			[]string{"home/*"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Deny},
		{"nil keys", iampolicy.OpBool, iampolicy.KeySecureTransport,
			[]string{"true"}, nil, iampolicy.Deny},
		// Present but empty is not the same as absent, and still compares.
		{"present but empty", iampolicy.OpStringEquals, iampolicy.KeyUsername,
			[]string{""}, iampolicy.ConditionKeys{iampolicy.KeyUsername: ""}, iampolicy.Allow},

		{"StringNotEquals other value", iampolicy.OpStringNotEquals, iampolicy.KeyUsername,
			[]string{"bob"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Allow},
		{"StringNotEquals same value", iampolicy.OpStringNotEquals, iampolicy.KeyUsername,
			[]string{"alice"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Deny},
		{"StringNotEquals is case-sensitive", iampolicy.OpStringNotEquals, iampolicy.KeyUsername,
			[]string{"alice"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "Alice"}, iampolicy.Allow},
		// Negated, the ORed values become "none of": one hit is enough to fail.
		{"StringNotEquals any of several", iampolicy.OpStringNotEquals, iampolicy.KeyUsername,
			[]string{"bob", "alice"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Deny},
		{"StringNotLike outside the pattern", iampolicy.OpStringNotLike, iampolicy.KeyS3Prefix,
			[]string{"home/alice/*"}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/bob/"}, iampolicy.Allow},
		{"StringNotLike inside the pattern", iampolicy.OpStringNotLike, iampolicy.KeyS3Prefix,
			[]string{"home/alice/*"}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/alice/docs/"}, iampolicy.Deny},
		{"StringEqualsIgnoreCase folds case", iampolicy.OpStringEqualsIgnoreCase, iampolicy.KeyPrincipalType,
			[]string{"assumedrole"}, iampolicy.ConditionKeys{iampolicy.KeyPrincipalType: "AssumedRole"}, iampolicy.Allow},
		{"StringEqualsIgnoreCase mismatch", iampolicy.OpStringEqualsIgnoreCase, iampolicy.KeyPrincipalType,
			[]string{"user"}, iampolicy.ConditionKeys{iampolicy.KeyPrincipalType: "AssumedRole"}, iampolicy.Deny},
		// Equality, not a glob: a * in the value is a literal.
		{"StringEqualsIgnoreCase has no wildcards", iampolicy.OpStringEqualsIgnoreCase, iampolicy.KeyPrincipalType,
			[]string{"*"}, iampolicy.ConditionKeys{iampolicy.KeyPrincipalType: "User"}, iampolicy.Deny},
		{"StringNotEqualsIgnoreCase folds case", iampolicy.OpStringNotEqualsIgnoreCase, iampolicy.KeyUsername,
			[]string{"ALICE"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Deny},
		{"StringNotEqualsIgnoreCase other value", iampolicy.OpStringNotEqualsIgnoreCase, iampolicy.KeyUsername,
			[]string{"BOB"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Allow},
		{"NotIpAddress outside CIDR", iampolicy.OpNotIPAddress, iampolicy.KeySourceIP,
			[]string{"10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "192.168.1.1"}, iampolicy.Allow},
		{"NotIpAddress inside CIDR", iampolicy.OpNotIPAddress, iampolicy.KeySourceIP,
			[]string{"10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "10.4.1.9"}, iampolicy.Deny},
		{"NotIpAddress inside any of several", iampolicy.OpNotIPAddress, iampolicy.KeySourceIP,
			[]string{"172.16.0.0/12", "10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "10.4.1.9"}, iampolicy.Deny},

		// Per AWS, a negated operator on an absent key holds.
		{"StringNotEquals absent key", iampolicy.OpStringNotEquals, iampolicy.KeyUsername,
			[]string{"alice"}, iampolicy.ConditionKeys{iampolicy.KeyUserID: "AROAOPS:deploy"}, iampolicy.Allow},
		{"StringNotLike absent key", iampolicy.OpStringNotLike, iampolicy.KeyS3Prefix,
			[]string{"home/*"}, nil, iampolicy.Allow},
		{"NotIpAddress absent key", iampolicy.OpNotIPAddress, iampolicy.KeySourceIP,
			[]string{"10.0.0.0/8"}, nil, iampolicy.Allow},
		{"StringEqualsIgnoreCase absent key", iampolicy.OpStringEqualsIgnoreCase, iampolicy.KeyUsername,
			[]string{"alice"}, nil, iampolicy.Deny},

		// Null true holds on an absent key, false on a present one, and a present
		// empty value is present.
		{"Null true absent key", iampolicy.OpNull, iampolicy.KeyUsername,
			[]string{"true"}, iampolicy.ConditionKeys{iampolicy.KeyUserID: "AROAOPS:deploy"}, iampolicy.Allow},
		{"Null true present key", iampolicy.OpNull, iampolicy.KeyUsername,
			[]string{"true"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Deny},
		{"Null true present but empty", iampolicy.OpNull, iampolicy.KeyUsername,
			[]string{"true"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: ""}, iampolicy.Deny},
		{"Null false present key", iampolicy.OpNull, iampolicy.KeyUsername,
			[]string{"false"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Allow},
		{"Null false absent key", iampolicy.OpNull, iampolicy.KeyUsername,
			[]string{"false"}, nil, iampolicy.Deny},
		{"Null ignores case", iampolicy.OpNull, iampolicy.KeyUsername,
			[]string{"TRUE"}, nil, iampolicy.Allow},
		{"Null values are ORed", iampolicy.OpNull, iampolicy.KeyUsername,
			[]string{"false", "true"}, nil, iampolicy.Allow},

		// IfExists holds on an absent key and otherwise is its base operator.
		{"StringEqualsIfExists absent key", iampolicy.OpStringEquals + iampolicy.IfExistsSuffix, iampolicy.KeyUsername,
			[]string{"alice"}, nil, iampolicy.Allow},
		{"StringEqualsIfExists match", iampolicy.OpStringEquals + iampolicy.IfExistsSuffix, iampolicy.KeyUsername,
			[]string{"alice"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}, iampolicy.Allow},
		{"StringEqualsIfExists mismatch", iampolicy.OpStringEquals + iampolicy.IfExistsSuffix, iampolicy.KeyUsername,
			[]string{"alice"}, iampolicy.ConditionKeys{iampolicy.KeyUsername: "bob"}, iampolicy.Deny},
		{"StringNotLikeIfExists absent key", iampolicy.OpStringNotLike + iampolicy.IfExistsSuffix, iampolicy.KeyS3Prefix,
			[]string{"home/*"}, nil, iampolicy.Allow},
		{"StringNotLikeIfExists inside the pattern", iampolicy.OpStringNotLike + iampolicy.IfExistsSuffix, iampolicy.KeyS3Prefix,
			[]string{"home/*"}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/alice/"}, iampolicy.Deny},
		{"IpAddressIfExists outside CIDR", iampolicy.OpIPAddress + iampolicy.IfExistsSuffix, iampolicy.KeySourceIP,
			[]string{"10.0.0.0/8"}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "192.168.1.1"}, iampolicy.Deny},
		{"BoolIfExists absent key", iampolicy.OpBool + iampolicy.IfExistsSuffix, iampolicy.KeySecureTransport,
			[]string{"true"}, nil, iampolicy.Allow},
		{"BoolIfExists mismatch", iampolicy.OpBool + iampolicy.IfExistsSuffix, iampolicy.KeySecureTransport,
			[]string{"true"}, iampolicy.ConditionKeys{iampolicy.KeySecureTransport: "false"}, iampolicy.Deny},

		// Date operators compare instants, so the spelling of either side does
		// not matter; the boundary decides the strict and inclusive forms.
		{"DateEquals same instant", iampolicy.OpDateEquals, iampolicy.KeyCurrentTime,
			[]string{"2026-10-01T12:00:00Z"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Allow},
		{"DateEquals across time zones", iampolicy.OpDateEquals, iampolicy.KeyCurrentTime,
			[]string{"2026-10-01T22:00:00+10:00"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Allow},
		{"DateEquals epoch value on ISO key", iampolicy.OpDateEquals, iampolicy.KeyCurrentTime,
			[]string{"1790856000"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Allow},
		{"DateEquals one second off", iampolicy.OpDateEquals, iampolicy.KeyCurrentTime,
			[]string{"2026-10-01T12:00:01Z"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Deny},
		{"DateNotEquals same instant", iampolicy.OpDateNotEquals, iampolicy.KeyEpochTime,
			[]string{"2026-10-01T12:00:00Z"}, iampolicy.ConditionKeys{iampolicy.KeyEpochTime: "1790856000"}, iampolicy.Deny},
		{"DateNotEquals another instant", iampolicy.OpDateNotEquals, iampolicy.KeyEpochTime,
			[]string{"2026-10-01"}, iampolicy.ConditionKeys{iampolicy.KeyEpochTime: "1790856000"}, iampolicy.Allow},
		{"DateLessThan before", iampolicy.OpDateLessThan, iampolicy.KeyCurrentTime,
			[]string{"2026-10-01T12:00:01Z"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Allow},
		{"DateLessThan at the boundary", iampolicy.OpDateLessThan, iampolicy.KeyCurrentTime,
			[]string{"2026-10-01T12:00:00Z"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Deny},
		{"DateLessThanEquals at the boundary", iampolicy.OpDateLessThanEquals, iampolicy.KeyCurrentTime,
			[]string{"2026-10-01T12:00:00Z"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Allow},
		{"DateLessThanEquals after", iampolicy.OpDateLessThanEquals, iampolicy.KeyCurrentTime,
			[]string{"2026-10-01T11:59:59Z"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Deny},
		{"DateGreaterThan after", iampolicy.OpDateGreaterThan, iampolicy.KeyEpochTime,
			[]string{"1790855999"}, iampolicy.ConditionKeys{iampolicy.KeyEpochTime: "1790856000"}, iampolicy.Allow},
		{"DateGreaterThan at the boundary", iampolicy.OpDateGreaterThan, iampolicy.KeyEpochTime,
			[]string{"1790856000"}, iampolicy.ConditionKeys{iampolicy.KeyEpochTime: "1790856000"}, iampolicy.Deny},
		{"DateGreaterThanEquals at the boundary", iampolicy.OpDateGreaterThanEquals, iampolicy.KeyEpochTime,
			[]string{"1790856000"}, iampolicy.ConditionKeys{iampolicy.KeyEpochTime: "1790856000"}, iampolicy.Allow},
		{"DateGreaterThanEquals before", iampolicy.OpDateGreaterThanEquals, iampolicy.KeyEpochTime,
			[]string{"2026-10-01T12:00:01Z"}, iampolicy.ConditionKeys{iampolicy.KeyEpochTime: "1790856000"}, iampolicy.Deny},
		{"DateLessThan values are ORed", iampolicy.OpDateLessThan, iampolicy.KeyCurrentTime,
			[]string{"2020-01-01", "2027-01-01"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Allow},
		// An unparseable value matches nothing, but does not stop the scan.
		{"DateLessThan skips an unparseable value", iampolicy.OpDateLessThan, iampolicy.KeyCurrentTime,
			[]string{"next week", "2027-01-01"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Allow},
		{"DateLessThan unparseable value alone", iampolicy.OpDateLessThan, iampolicy.KeyCurrentTime,
			[]string{"next week"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Deny},
		// Policy variables are not supported with date operators: compared as written.
		{"DateEquals does not expand a variable", iampolicy.OpDateEquals, iampolicy.KeyCurrentTime,
			[]string{"${aws:CurrentTime}"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Deny},
		{"DateLessThan absent key", iampolicy.OpDateLessThan, iampolicy.KeyCurrentTime,
			[]string{"2027-01-01"}, nil, iampolicy.Deny},
		{"DateNotEquals absent key", iampolicy.OpDateNotEquals, iampolicy.KeyCurrentTime,
			[]string{"2027-01-01"}, nil, iampolicy.Allow},
		{"DateGreaterThanIfExists absent key", iampolicy.OpDateGreaterThan + iampolicy.IfExistsSuffix, iampolicy.KeyCurrentTime,
			[]string{"2027-01-01"}, nil, iampolicy.Allow},
		{"DateGreaterThanIfExists present key", iampolicy.OpDateGreaterThan + iampolicy.IfExistsSuffix, iampolicy.KeyCurrentTime,
			[]string{"2027-01-01"}, iampolicy.ConditionKeys{iampolicy.KeyCurrentTime: "2026-10-01T12:00:00Z"}, iampolicy.Deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := condDoc(tt.operator, tt.key, tt.values...)
			got := iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
				[]iampolicy.PolicyDocument{d}, tt.keys)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Separate condition blocks are ANDed: every one must hold.
func TestEvaluateWithKeys_MultipleConditionsAreAnded(t *testing.T) {
	d := condDoc(iampolicy.OpIPAddress, iampolicy.KeySourceIP, "10.0.0.0/8")
	d.Statement[0].Condition[iampolicy.OpBool] = map[string]iampolicy.ConditionValue{
		iampolicy.KeySecureTransport: {"true"},
	}

	both := iampolicy.ConditionKeys{
		iampolicy.KeySourceIP: "10.1.2.3", iampolicy.KeySecureTransport: "true",
	}
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k", []iampolicy.PolicyDocument{d}, both))

	plaintext := iampolicy.ConditionKeys{
		iampolicy.KeySourceIP: "10.1.2.3", iampolicy.KeySecureTransport: "false",
	}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k", []iampolicy.PolicyDocument{d}, plaintext))
}

// An absent key satisfies its negated condition and nothing more: the other
// conditions are still ANDed. Map order is random, so each case runs repeatedly.
func TestEvaluateWithKeys_NegatedAbsentKeyStillAndsTheRest(t *testing.T) {
	separateBlocks := condDoc(iampolicy.OpStringNotEquals, iampolicy.KeyUsername, "bob")
	separateBlocks.Statement[0].Condition[iampolicy.OpIPAddress] = map[string]iampolicy.ConditionValue{
		iampolicy.KeySourceIP: {"10.0.0.0/8"},
	}
	sameBlock := condDoc(iampolicy.OpStringNotEquals, iampolicy.KeyUsername, "bob")
	sameBlock.Statement[0].Condition[iampolicy.OpStringNotEquals][iampolicy.KeyPrincipalAccount] =
		iampolicy.ConditionValue{"111122223333"}

	keys := iampolicy.ConditionKeys{
		iampolicy.KeySourceIP: "192.0.2.10", iampolicy.KeyPrincipalAccount: "111122223333",
	}
	for range 50 {
		assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
			[]iampolicy.PolicyDocument{separateBlocks}, keys), "separate blocks")
		assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
			[]iampolicy.PolicyDocument{sameBlock}, keys), "same block")
	}
}

// A Deny whose condition does not hold does not fire, so the Allow stands.
func TestEvaluateWithKeys_ConditionalDenyRespectsKeys(t *testing.T) {
	allow := doc("Allow", "s3:*", "*")
	deny := condDoc(iampolicy.OpBool, iampolicy.KeySecureTransport, "false")
	deny.Statement[0].Effect = iampolicy.EffectDeny
	policies := []iampolicy.PolicyDocument{allow, deny}

	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
		policies, iampolicy.ConditionKeys{iampolicy.KeySecureTransport: "true"}))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
		policies, iampolicy.ConditionKeys{iampolicy.KeySecureTransport: "false"}))
}

// A request address the operator cannot parse is unresolvable input, so it
// takes the same arm as every other operator: the Deny fires rather than
// silently disappearing. host:port is the shape a door is most likely to pass.
func TestEvaluateWithKeys_UnparseableSourceIPStillDenies(t *testing.T) {
	allow := doc("Allow", "s3:*", "*")
	deny := condDoc(iampolicy.OpIPAddress, iampolicy.KeySourceIP, "10.0.0.0/8")
	deny.Statement[0].Effect = iampolicy.EffectDeny
	policies := []iampolicy.PolicyDocument{allow, deny}

	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
		policies, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "10.4.1.9:54321"}),
		"a Deny conditioned on aws:SourceIp must survive an address it cannot parse")

	// The mirror: the same unparseable address must not satisfy an Allow.
	conditioned := condDoc(iampolicy.OpIPAddress, iampolicy.KeySourceIP, "10.0.0.0/8")
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
		[]iampolicy.PolicyDocument{conditioned}, iampolicy.ConditionKeys{iampolicy.KeySourceIP: "10.4.1.9:54321"}))
}

// A condition value may carry a variable, resolved against the same context
// the key itself is read from.
func TestEvaluateWithKeys_ConditionValueResolvesVariables(t *testing.T) {
	d := condDoc(iampolicy.OpStringLike, iampolicy.KeyS3Prefix, "home/${aws:username}/*")

	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::b",
		[]iampolicy.PolicyDocument{d}, iampolicy.ConditionKeys{
			iampolicy.KeyS3Prefix: "home/alice/reports", iampolicy.KeyUsername: "alice",
		}))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::b",
		[]iampolicy.PolicyDocument{d}, iampolicy.ConditionKeys{
			iampolicy.KeyS3Prefix: "home/bob/reports", iampolicy.KeyUsername: "alice",
		}))

	// Unresolvable: the door supplies s3:prefix but not aws:username.
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::b",
		[]iampolicy.PolicyDocument{d}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/alice/reports"}))

	// A username holding a wildcard is compared literally.
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::b",
		[]iampolicy.PolicyDocument{d}, iampolicy.ConditionKeys{
			iampolicy.KeyS3Prefix: "home/bob/reports", iampolicy.KeyUsername: "*",
		}))
}

// StringEquals compares the resolved value exactly, with no wildcard meaning.
func TestEvaluateWithKeys_StringEqualsResolvesVariables(t *testing.T) {
	d := condDoc(iampolicy.OpStringEquals, iampolicy.KeyS3Prefix, "home/${aws:username}")

	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::b",
		[]iampolicy.PolicyDocument{d}, iampolicy.ConditionKeys{
			iampolicy.KeyS3Prefix: "home/alice", iampolicy.KeyUsername: "alice",
		}))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::b",
		[]iampolicy.PolicyDocument{d}, iampolicy.ConditionKeys{
			iampolicy.KeyS3Prefix: "home/alice/x", iampolicy.KeyUsername: "alice",
		}))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::b",
		[]iampolicy.PolicyDocument{d}, iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "home/alice"}))
}

// The guarantee a negated Deny exists for: no request can stop it firing by
// leaving the key out, whatever else the request carries.
func TestEvaluateWithKeys_NegatedDenyFiresOnAbsentKey(t *testing.T) {
	for _, tt := range []struct{ op, key, value string }{
		{iampolicy.OpStringNotEquals, iampolicy.KeyUsername, "alice"},
		{iampolicy.OpStringNotEqualsIgnoreCase, iampolicy.KeyUsername, "alice"},
		{iampolicy.OpStringNotLike, iampolicy.KeyS3Prefix, "home/*"},
		{iampolicy.OpNotIPAddress, iampolicy.KeySourceIP, "10.0.0.0/8"},
	} {
		// An unregistered pair is unenforceable and fires regardless, which
		// would pass this test without reaching the absent-key path.
		require.True(t, iampolicy.SupportedCondition(tt.op, tt.key), "%s on %s", tt.op, tt.key)
		deny := condDoc(tt.op, tt.key, tt.value)
		deny.Statement[0].Effect = iampolicy.EffectDeny
		for _, keys := range []iampolicy.ConditionKeys{nil, {iampolicy.KeyPrincipalAccount: "111122223333"}} {
			assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
				[]iampolicy.PolicyDocument{doc("Allow", "s3:*", "*"), deny}, keys), "%s with keys %v", tt.op, keys)
		}
	}
}

// Input a negated operator cannot resolve narrows access just as it does for
// the positive form: the negation must not turn a fail-closed Deny into a no-op.
func TestEvaluateWithKeys_NegatedOperatorFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		op     string
		key    string
		value  string
		actual string
	}{
		{"unresolvable variable", iampolicy.OpStringNotEquals, iampolicy.KeyS3Prefix,
			"home/${aws:username}", "home/alice"},
		{"unresolvable variable, case-insensitive", iampolicy.OpStringNotEqualsIgnoreCase, iampolicy.KeyS3Prefix,
			"home/${aws:username}", "home/alice"},
		{"unresolvable variable in a pattern", iampolicy.OpStringNotLike, iampolicy.KeyS3Prefix,
			"home/${aws:username}/*", "home/alice/x"},
		{"unparseable request address", iampolicy.OpNotIPAddress, iampolicy.KeySourceIP,
			"10.0.0.0/8", "10.4.1.9:54321"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := iampolicy.ConditionKeys{tt.key: tt.actual}

			allow := condDoc(tt.op, tt.key, tt.value)
			assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
				[]iampolicy.PolicyDocument{allow}, keys), "the Allow must not grant")

			deny := condDoc(tt.op, tt.key, tt.value)
			deny.Statement[0].Effect = iampolicy.EffectDeny
			assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
				[]iampolicy.PolicyDocument{doc("Allow", "s3:*", "*"), deny}, keys), "the Deny must fire")
		})
	}
}

// IfExists only relaxes the absent case: input the base operator cannot resolve
// on a present key still narrows access, an Allow not granting and a Deny firing.
func TestEvaluateWithKeys_IfExistsFailsClosedOnPresentKey(t *testing.T) {
	tests := []struct {
		name   string
		op     string
		key    string
		value  string
		actual string
	}{
		{"unresolvable variable", iampolicy.OpStringEquals, iampolicy.KeyS3Prefix,
			"home/${aws:username}", "home/alice"},
		{"unresolvable variable under negation", iampolicy.OpStringNotLike, iampolicy.KeyS3Prefix,
			"home/${aws:username}/*", "home/alice/x"},
		{"unparseable request address", iampolicy.OpIPAddress, iampolicy.KeySourceIP,
			"10.0.0.0/8", "10.4.1.9:54321"},
		{"unparseable request address under negation", iampolicy.OpNotIPAddress, iampolicy.KeySourceIP,
			"10.0.0.0/8", "10.4.1.9:54321"},
		{"unparseable request date", iampolicy.OpDateLessThan, iampolicy.KeyCurrentTime,
			"2027-01-01", "2026-10-01 12:00:00"},
		{"unparseable request date under negation", iampolicy.OpDateNotEquals, iampolicy.KeyEpochTime,
			"2027-01-01", "1790856000.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := tt.op + iampolicy.IfExistsSuffix
			require.True(t, iampolicy.SupportedCondition(op, tt.key), "%s on %s", op, tt.key)
			keys := iampolicy.ConditionKeys{tt.key: tt.actual}

			allow := condDoc(op, tt.key, tt.value)
			assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
				[]iampolicy.PolicyDocument{allow}, keys), "the Allow must not grant")

			deny := condDoc(op, tt.key, tt.value)
			deny.Statement[0].Effect = iampolicy.EffectDeny
			assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
				[]iampolicy.PolicyDocument{doc("Allow", "s3:*", "*"), deny}, keys), "the Deny must fire")
		})
	}
}

// NullIfExists is not an operator, so a statement carrying it is unenforceable
// and fails closed rather than being read as Null.
func TestEvaluateWithKeys_NullIfExistsFailsClosed(t *testing.T) {
	op := iampolicy.OpNull + iampolicy.IfExistsSuffix
	allow := condDoc(op, iampolicy.KeyUsername, "true")
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
		[]iampolicy.PolicyDocument{allow}, nil))

	deny := condDoc(op, iampolicy.KeyUsername, "false")
	deny.Statement[0].Effect = iampolicy.EffectDeny
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::b/k",
		[]iampolicy.PolicyDocument{doc("Allow", "s3:*", "*"), deny}, nil))
}

// A reference the evaluator does not support makes a condition non-matching,
// even when the request value contains the placeholder text literally.
func TestEvaluateWithKeys_UnsupportedReferenceDoesNotMatch(t *testing.T) {
	for _, op := range []string{iampolicy.OpStringEquals, iampolicy.OpStringLike} {
		d := condDoc(op, iampolicy.KeyS3Prefix, "reports/${quarter}")
		assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::b",
			[]iampolicy.PolicyDocument{d}, iampolicy.ConditionKeys{
				iampolicy.KeyS3Prefix: "reports/${quarter}", iampolicy.KeyUsername: "alice",
			}), op)
	}
}

// Spot-check that common AWS operators outside the allowlist stay unsupported.
// The table-vs-matcher agreement itself is pinned in conditions_internal_test.go,
// which iterates the allowlist rather than a hardcoded copy.
func TestSupportedCondition_MatchesImplementedOperators(t *testing.T) {
	implemented := []string{
		iampolicy.OpStringEquals, iampolicy.OpStringNotEquals,
		iampolicy.OpStringEqualsIgnoreCase, iampolicy.OpStringNotEqualsIgnoreCase,
		iampolicy.OpStringLike, iampolicy.OpStringNotLike,
		iampolicy.OpIPAddress, iampolicy.OpNotIPAddress, iampolicy.OpBool,
	}
	keys := []string{
		iampolicy.KeySourceIP, iampolicy.KeyS3Prefix, iampolicy.KeySecureTransport,
		iampolicy.KeyUsername, iampolicy.KeyPrincipalAccount,
	}
	for _, key := range keys {
		for _, op := range []string{"DateGreaterThan", "ArnLike", "NumericLessThan"} {
			assert.False(t, iampolicy.SupportedCondition(op, key),
				"operator %q on %q is advertised but not implemented", op, key)
		}
		supported := 0
		for _, op := range implemented {
			if iampolicy.SupportedCondition(op, key) {
				supported++
			}
		}
		assert.Positive(t, supported, "key %q supports no implemented operator", key)
	}
}
