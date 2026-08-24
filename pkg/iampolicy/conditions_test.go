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
