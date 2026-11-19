package iampolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	endpointAction   = "s3:GetObject"
	endpointResource = "arn:aws:s3:::reports/q3.csv"
)

// endpointDoc parses one endpoint policy as the gate receives it.
func endpointDoc(t *testing.T, statements string) iampolicy.PolicyDocument {
	t.Helper()
	var doc iampolicy.PolicyDocument
	require.NoError(t, json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":[`+statements+`]}`), &doc))
	return doc
}

func endpointDecision(t *testing.T, statements string, keys iampolicy.ConditionKeys) iampolicy.Decision {
	t.Helper()
	return iampolicy.EvaluateEndpointPolicy(endpointAction, endpointResource, endpointDoc(t, statements), keys)
}

// An endpoint policy names every principal in one of the forms AWS documents,
// and each selects every caller.
func TestEndpointPolicy_EveryPrincipalFormAllows(t *testing.T) {
	for _, principal := range []string{`"*"`, `{"AWS":"*"}`, `{"AWS":["*"]}`} {
		stmt := `{"Effect":"Allow","Principal":` + principal + `,"Action":"s3:*","Resource":"*"}`
		assert.Equal(t, iampolicy.Allow, endpointDecision(t, stmt, nil), "Principal %s", principal)
	}
}

// Any other Principal, or none, is something the gate cannot enforce, so an
// Allow carrying it grants nothing and a Deny carrying it denies.
func TestEndpointPolicy_OtherPrincipalsFailClosed(t *testing.T) {
	for _, principal := range []string{
		``, `"Principal":{"AWS":"arn:aws:iam::123456789012:root"},`, `"Principal":{"Service":"*"},`,
		`"Principal":{"AWS":["*","arn:aws:iam::123456789012:root"]},`, `"Principal":"arn:aws:iam::123456789012:root",`,
	} {
		allow := `{"Effect":"Allow",` + principal + `"Action":"s3:*","Resource":"*"}`
		assert.Equal(t, iampolicy.Deny, endpointDecision(t, allow, nil), "Allow with %q grants nothing", principal)

		deny := `{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"},` +
			`{"Effect":"Deny",` + principal + `"Action":"s3:GetObject","Resource":"*"}`
		assert.Equal(t, iampolicy.Deny, endpointDecision(t, deny, nil), "Deny with %q still denies", principal)
	}
}

// Both gates must allow: an endpoint policy's own Deny wins over its Allow, and
// an action it does not name is implicitly denied.
func TestEndpointPolicy_DenyAndImplicitDeny(t *testing.T) {
	allowAll := `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}`
	denyBucket := `{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::reports/*"}`
	assert.Equal(t, iampolicy.Deny, endpointDecision(t, allowAll+","+denyBucket, nil))

	onlyPut := `{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"*"}`
	assert.Equal(t, iampolicy.Deny, endpointDecision(t, onlyPut, nil))
}

// The endpoint mode leaves identity evaluation as it was: a Principal there
// still fails closed, and aws:PrincipalArn is still not a key it enforces.
func TestEndpointPolicy_IdentityEvaluationUnchanged(t *testing.T) {
	doc := endpointDoc(t, `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}`)
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys(endpointAction, endpointResource, []iampolicy.PolicyDocument{doc}, nil))

	noPrincipal := endpointDoc(t, `{"Effect":"Allow","Action":"*","Resource":"*",
		"Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/*"}}}`)
	keys := iampolicy.ConditionKeys{iampolicy.KeyPrincipalArn: doorPrincipalArn}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys(endpointAction, endpointResource, []iampolicy.PolicyDocument{noPrincipal}, keys))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpArnLike, iampolicy.KeyPrincipalArn))
}

// aws:PrincipalArn takes the ARN and string operators AWS gives it, and an
// absent key evaluates as AWS evaluates one.
func TestEndpointPolicy_PrincipalArnCondition(t *testing.T) {
	keys := iampolicy.ConditionKeys{iampolicy.KeyPrincipalArn: doorPrincipalArn}
	cases := []struct {
		name, condition string
		keys            iampolicy.ConditionKeys
		want            iampolicy.Decision
	}{
		{"ArnLike matches", `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/*"}}`, keys, iampolicy.Allow},
		{"ArnEquals other", `{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::999999999999:user/x"}}`, keys, iampolicy.Deny},
		{"StringEquals matches", `{"StringEquals":{"aws:PrincipalArn":"` + doorPrincipalArn + `"}}`, keys, iampolicy.Allow},
		{"StringLike matches", `{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*"}}`, keys, iampolicy.Allow},
		{"ArnNotLike on absent key", `{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/*"}}`, nil, iampolicy.Allow},
		{"ArnLike on absent key", `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*"}}`, nil, iampolicy.Deny},
		{"Null true on absent key", `{"Null":{"aws:PrincipalArn":"true"}}`, nil, iampolicy.Allow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stmt := `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":` + tc.condition + `}`
			assert.Equal(t, tc.want, endpointDecision(t, stmt, tc.keys))
		})
	}
}

func TestSupportedEndpointCondition(t *testing.T) {
	assert.True(t, iampolicy.SupportedEndpointCondition(iampolicy.OpArnLike, iampolicy.KeyPrincipalArn))
	assert.True(t, iampolicy.SupportedEndpointCondition(iampolicy.OpArnNotEquals+iampolicy.IfExistsSuffix, iampolicy.KeyPrincipalArn))
	assert.True(t, iampolicy.SupportedEndpointCondition(iampolicy.OpNull, iampolicy.KeyPrincipalArn))
	assert.False(t, iampolicy.SupportedEndpointCondition(iampolicy.OpNull+iampolicy.IfExistsSuffix, iampolicy.KeyPrincipalArn))
	assert.False(t, iampolicy.SupportedEndpointCondition(iampolicy.OpIPAddress, iampolicy.KeyPrincipalArn))
	assert.True(t, iampolicy.SupportedEndpointCondition(iampolicy.OpStringEquals, iampolicy.KeySourceVpce), "identity keys stay usable")
	assert.False(t, iampolicy.SupportedEndpointCondition(iampolicy.OpStringEquals, "aws:MultiFactorAuthPresent"))
}

// A write path refuses exactly what the gate would fail closed on, naming the
// statement, so no stored endpoint policy is silently narrower than written.
func TestCheckEndpointPolicy(t *testing.T) {
	ok := `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}`
	require.NoError(t, iampolicy.CheckEndpointPolicy(endpointDoc(t, ok)))
	require.NoError(t, iampolicy.CheckEndpointPolicy(endpointDoc(t, ok+`,{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:DeleteObject","Resource":"*",
		"Condition":{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/admin"}}}`)))

	cases := []struct{ name, stmt, want string }{
		{"specific principal", `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"*","Resource":"*"}`, "statement 1: Principal is not supported"},
		{"no principal", `{"Effect":"Allow","Action":"*","Resource":"*"}`, "statement 1: Principal is not supported"},
		{"unknown key", `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}`,
			"statement 1: condition Bool on aws:MultiFactorAuthPresent is not supported"},
		{"bad effect", `{"Effect":"Maybe","Principal":"*","Action":"*","Resource":"*"}`, `statement 1: Effect "Maybe" is not Allow or Deny`},
		{"action pair", `{"Effect":"Allow","Principal":"*","Action":"*","NotAction":"s3:GetObject","Resource":"*"}`, "statement 1: Action/NotAction is not supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.EqualError(t, iampolicy.CheckEndpointPolicy(endpointDoc(t, ok+","+tc.stmt)), tc.want)
		})
	}
}
