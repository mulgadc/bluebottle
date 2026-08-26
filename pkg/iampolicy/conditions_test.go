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

	// Right key, wrong operator.
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpStringEquals, iampolicy.KeySourceIP))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpIPAddress, iampolicy.KeyUsername))
	// MFA is hard-dropped: spinifex has no MFA, so the key could never be true.
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpBool, "aws:MultiFactorAuthPresent"))
	assert.False(t, iampolicy.SupportedCondition("DateGreaterThan", "aws:CurrentTime"))
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

// Spot-check that common AWS operators outside the allowlist stay unsupported.
// The table-vs-matcher agreement itself is pinned in conditions_internal_test.go,
// which iterates the allowlist rather than a hardcoded copy.
func TestSupportedCondition_MatchesImplementedOperators(t *testing.T) {
	implemented := []string{
		iampolicy.OpStringEquals, iampolicy.OpStringLike,
		iampolicy.OpIPAddress, iampolicy.OpBool,
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
