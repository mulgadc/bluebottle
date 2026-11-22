package iampolicy_test

import (
	"testing"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	endpointAction   = "s3:GetObject"
	endpointResource = "arn:aws:s3:::reports/q3.csv"
	allowAll         = `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}`
)

// endpointDoc parses an endpoint policy as the gate receives it.
func endpointDoc(t *testing.T, version, statements string) iampolicy.PolicyDocument {
	t.Helper()
	doc, err := iampolicy.ParseEndpointPolicy([]byte(`{"Version":"` + version + `","Statement":[` + statements + `]}`))
	require.NoError(t, err)
	return doc
}

func endpointDecision(t *testing.T, statements string, keys iampolicy.ConditionKeys) iampolicy.Decision {
	t.Helper()
	return iampolicy.EvaluateEndpointPolicy(endpointAction, endpointResource, endpointDoc(t, iampolicy.Version2012, statements), keys)
}

// The caller the gate describes: alice in doorAccount.
var alice = iampolicy.ConditionKeys{
	iampolicy.KeyPrincipalArn:     doorPrincipalArn,
	iampolicy.KeyPrincipalAccount: doorAccount,
	iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeUser,
}

var bob = iampolicy.ConditionKeys{
	iampolicy.KeyPrincipalArn:     "arn:aws:iam::" + doorAccount + ":user/bob",
	iampolicy.KeyPrincipalAccount: doorAccount,
	iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeUser,
}

func principal(effect, p string) string {
	return `{"Effect":"` + effect + `","Principal":` + p + `,"Action":"s3:*","Resource":"*"}`
}

func TestEndpointPolicy_EveryPrincipalFormAllows(t *testing.T) {
	for _, p := range []string{`"*"`, `{"AWS":"*"}`, `{"AWS":["*"]}`} {
		assert.Equal(t, iampolicy.Allow, endpointDecision(t, principal("Allow", p), nil), "Principal %s", p)
	}
}

// On a gateway endpoint an account principal, by ID or root ARN, names that
// account's root user only, as AWS documents; users and roles are named with
// aws:PrincipalArn instead.
func TestEndpointPolicy_AccountPrincipalNamesTheRootUserOnly(t *testing.T) {
	root := iampolicy.ConditionKeys{
		iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeAccount,
		iampolicy.KeyPrincipalAccount: doorAccount,
	}
	cases := []struct {
		name, principal string
		keys            iampolicy.ConditionKeys
		want            iampolicy.Decision
	}{
		{"account ID, its root", `{"AWS":"` + doorAccount + `"}`, root, iampolicy.Allow},
		{"root ARN, its root", `{"AWS":"arn:aws:iam::` + doorAccount + `:root"}`, root, iampolicy.Allow},
		{"account ID, a user in it", `{"AWS":"` + doorAccount + `"}`, alice, iampolicy.Deny},
		{"another account", `{"AWS":["999999999999"]}`, root, iampolicy.Deny},
		{"one of a list", `{"AWS":["999999999999","` + doorAccount + `"]}`, root, iampolicy.Allow},
		{"caller undescribed", `{"AWS":"` + doorAccount + `"}`, nil, iampolicy.Deny},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, endpointDecision(t, principal("Allow", tc.principal), tc.keys))
		})
	}

	// A Deny naming the account denies its root, and everyone when the door
	// cannot say who the caller is, but not the account's users.
	policy := allowAll + "," + principal("Deny", `{"AWS":"`+doorAccount+`"}`)
	assert.Equal(t, iampolicy.Deny, endpointDecision(t, policy, root))
	assert.Equal(t, iampolicy.Allow, endpointDecision(t, policy, alice))
	assert.Equal(t, iampolicy.Deny, endpointDecision(t, policy, nil))
}

// A Principal the gate cannot match, or none, fails closed: an Allow carrying it
// grants nothing and a Deny carrying it denies.
func TestEndpointPolicy_UnmatchablePrincipalsFailClosed(t *testing.T) {
	for _, p := range []string{
		`{"Service":"s3.amazonaws.com"}`, `{"AWS":"arn:aws:sts::111122223333:assumed-role/ops/s"}`,
		`{"AWS":"alice"}`, `{"AWS":"*","Service":"*"}`, `{"AWS":"` + doorPrincipalArn + `"}`, `{"AWS":"arn:aws:iam::111122223333:role/ops"}`, `{"AWS":[]}`, `"arn:aws:iam::111122223333:root"`,
	} {
		assert.Equal(t, iampolicy.Deny, endpointDecision(t, principal("Allow", p), alice), "Allow with %s grants nothing", p)
		assert.Equal(t, iampolicy.Deny, endpointDecision(t, allowAll+","+principal("Deny", p), bob), "Deny with %s still denies", p)
	}
	noPrincipal := `{"Effect":"Allow","Action":"*","Resource":"*"}`
	assert.Equal(t, iampolicy.Deny, endpointDecision(t, noPrincipal, alice))
}

// Both gates must allow: an endpoint policy's own Deny wins over its Allow, and
// an action it does not name is implicitly denied.
func TestEndpointPolicy_DenyAndImplicitDeny(t *testing.T) {
	denyBucket := `{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::reports/*"}`
	assert.Equal(t, iampolicy.Deny, endpointDecision(t, allowAll+","+denyBucket, nil))

	onlyPut := `{"Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"*"}`
	assert.Equal(t, iampolicy.Deny, endpointDecision(t, onlyPut, nil))
}

// The endpoint mode leaves identity evaluation as it was: a Principal there
// still fails closed, and aws:PrincipalArn is still not a key it enforces.
func TestEndpointPolicy_IdentityEvaluationUnchanged(t *testing.T) {
	doc := endpointDoc(t, iampolicy.Version2012, allowAll)
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys(endpointAction, endpointResource, []iampolicy.PolicyDocument{doc}, nil))

	byArn := endpointDoc(t, iampolicy.Version2012, `{"Effect":"Allow","Action":"*","Resource":"*",
		"Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/*"}}}`)
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys(endpointAction, endpointResource, []iampolicy.PolicyDocument{byArn}, alice))
	assert.False(t, iampolicy.SupportedCondition(iampolicy.OpArnLike, iampolicy.KeyPrincipalArn))
}

// aws:PrincipalArn takes the ARN and string operators AWS gives it, and an
// absent key evaluates as AWS evaluates one.
func TestEndpointPolicy_PrincipalArnCondition(t *testing.T) {
	cases := []struct {
		name, condition string
		keys            iampolicy.ConditionKeys
		want            iampolicy.Decision
	}{
		{"ArnLike matches", `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:user/*"}}`, alice, iampolicy.Allow},
		{"ArnEquals other", `{"ArnEquals":{"aws:PrincipalArn":"arn:aws:iam::999999999999:user/x"}}`, alice, iampolicy.Deny},
		{"StringEquals matches", `{"StringEquals":{"aws:PrincipalArn":"` + doorPrincipalArn + `"}}`, alice, iampolicy.Allow},
		{"StringLike matches", `{"StringLike":{"aws:PrincipalArn":"arn:aws:iam::*"}}`, alice, iampolicy.Allow},
		{"ArnNotLike on absent key", `{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/*"}}`, nil, iampolicy.Allow},
		{"ArnLike on absent key", `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*"}}`, nil, iampolicy.Deny},
		{"Null true on absent key", `{"Null":{"aws:PrincipalArn":"true"}}`, nil, iampolicy.Allow},
		{"key named in another case", `{"ArnLike":{"AWS:principalarn":"arn:aws:iam::*:user/alice"}}`, alice, iampolicy.Allow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stmt := `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":` + tc.condition + `}`
			assert.Equal(t, tc.want, endpointDecision(t, stmt, tc.keys))
		})
	}
}

// The common endpoint-policy shape: allow everything, deny one principal by
// ARN. The named caller is denied and any other still allowed.
func TestEndpointPolicy_PrincipalArnDenyOverridesABroadAllow(t *testing.T) {
	policy := allowAll + `,{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*",
		"Condition":{"ArnEquals":{"aws:PrincipalArn":"` + doorPrincipalArn + `"}}}`
	assert.Equal(t, iampolicy.Deny, endpointDecision(t, policy, alice))
	assert.Equal(t, iampolicy.Allow, endpointDecision(t, policy, bob))
}

// A condition block with no operand would otherwise hold vacuously, so an Allow
// carrying one would grant unconditionally; it fails closed instead.
func TestEndpointPolicy_MalformedConditionsFailClosed(t *testing.T) {
	for _, condition := range []string{
		`{"ArnEquals":null}`, `{"ArnEquals":{}}`, `{"StringEquals":{"aws:SourceVpce":null}}`, `{"StringEquals":{"aws:SourceVpce":[]}}`,
		`{"Null":{"aws:SourceVpce":"maybe"}}`, `{"IpAddress":{"aws:VpcSourceIp":"10.0.0.0/33"}}`, `{"NotIpAddress":{"aws:VpcSourceIp":"nope"}}`,
		`{"DateGreaterThan":{"aws:CurrentTime":"soon"}}`, `{"NumericLessThan":{"aws:EpochTime":"ten"}}`, `{"Bool":{"aws:SecureTransport":"yes"}}`,
	} {
		allow := `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":` + condition + `}`
		assert.Equal(t, iampolicy.Deny, endpointDecision(t, allow, alice), "Allow with %s grants nothing", condition)
		require.Error(t, iampolicy.CheckEndpointPolicy(endpointDoc(t, iampolicy.Version2012, allow)), condition)

		deny := allowAll + `,{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*","Condition":` + condition + `}`
		assert.Equal(t, iampolicy.Deny, endpointDecision(t, deny, alice), "Deny with %s still denies", condition)
	}
}

// A Deny that names no action or no resource is refused at write and, injected
// past it, still denies at the gate rather than selecting nothing.
func TestEndpointPolicy_DenyWithoutASelectorFailsClosed(t *testing.T) {
	for _, deny := range []string{
		`{"Effect":"Deny","Principal":"*","Resource":"arn:aws:s3:::reports/*"}`,
		`{"Effect":"Deny","Principal":"*","Action":"s3:GetObject"}`,
	} {
		assert.Equal(t, iampolicy.Deny, endpointDecision(t, allowAll+","+deny, alice), deny)
	}
}

// Two spellings of one key in a block are separate tests on AWS, both of which
// must hold; merged, either value would match, so the policy is refused.
func TestParseEndpointPolicy_RefusesAKeyNamedTwice(t *testing.T) {
	_, err := iampolicy.ParseEndpointPolicy([]byte(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*",
		"Condition":{"StringEquals":{"aws:PrincipalAccount":"111111111111","AWS:principalaccount":"222222222222"}}}}`))
	require.EqualError(t, err, "statement 0: condition StringEquals names aws:PrincipalAccount twice")
}

// An empty Condition would read as none and make an Allow unconditional, so it
// is refused; a statement that omits Condition is unconditional as written.
func TestParseEndpointPolicy_RefusesAnEmptyCondition(t *testing.T) {
	for _, condition := range []string{`{}`, `null`, ` { } `} {
		_, err := iampolicy.ParseEndpointPolicy([]byte(`{"Version":"2012-10-17","Statement":[` + allowAll + `,` +
			`{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":` + condition + `}]}`))
		require.EqualError(t, err, "statement 1: the Condition element is empty; omit it for a statement with no condition", condition)
	}
	_, err := iampolicy.ParseEndpointPolicy([]byte(`{"Version":"2012-10-17","Statement":` + allowAll + `}`))
	require.NoError(t, err)
}

// The empty-selector rule is the endpoint mode's: an identity Deny missing its
// Action still selects nothing, as before.
func TestEvaluate_IdentityDenyWithoutAnActionSelectsNothing(t *testing.T) {
	policies := []iampolicy.PolicyDocument{{Version: iampolicy.Version2012, Statement: []iampolicy.Statement{
		{Effect: "Allow", Action: iampolicy.StringOrArr{"*"}, Resource: iampolicy.StringOrArr{"*"}},
		{Effect: "Deny", Principal: []byte(`"*"`), Resource: iampolicy.StringOrArr{"*"}},
	}}}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys(endpointAction, endpointResource, policies, nil))
}

// AWS reads a lone statement object as a one-statement array.
func TestParseEndpointPolicy_StatementObject(t *testing.T) {
	doc, err := iampolicy.ParseEndpointPolicy([]byte(`{"Version":"2012-10-17","Statement":` + allowAll + `}`))
	require.NoError(t, err)
	require.Len(t, doc.Statement, 1)
	require.NoError(t, iampolicy.CheckEndpointPolicy(doc))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateEndpointPolicy(endpointAction, endpointResource, doc, nil))

	_, err = iampolicy.ParseEndpointPolicy([]byte(`{"Statement":"Allow"}`))
	require.Error(t, err)
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
	accepted := []struct{ version, stmt string }{
		{iampolicy.Version2012, principal("Allow", `{"AWS":["`+doorAccount+`","arn:aws:iam::`+doorAccount+`:root"]}`)},
		{iampolicy.Version2012, `{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::home/${aws:username}/*",
			"Condition":{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/admin"}}}`},
		// Before 2012-10-17 a ${...} is literal text, so there is nothing to resolve.
		{iampolicy.Version2008, `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*",
			"Condition":{"StringEquals":{"aws:PrincipalArn":"${aws:PrincipalArn}"}}}`},
	}
	for _, tc := range accepted {
		require.NoError(t, iampolicy.CheckEndpointPolicy(endpointDoc(t, tc.version, allowAll+","+tc.stmt)), tc.stmt)
	}

	refused := []struct{ name, stmt, want string }{
		{"service principal", principal("Allow", `{"Service":"s3.amazonaws.com"}`), `statement 1: Principal must be "*" or name AWS accounts; name users and roles with aws:PrincipalArn`},
		{"no principal", `{"Effect":"Allow","Action":"*","Resource":"*"}`, `statement 1: Principal must be "*" or name AWS accounts; name users and roles with aws:PrincipalArn`},
		{"unknown key", `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}`,
			"statement 1: condition Bool on aws:MultiFactorAuthPresent is not supported"},
		{"bad effect", `{"Effect":"Maybe","Principal":"*","Action":"*","Resource":"*"}`, `statement 1: Effect "Maybe" is not Allow or Deny`},
		{"empty condition", `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*","Condition":{"ArnEquals":null}}`,
			"statement 1: condition ArnEquals names no key"},
		{"bad Null operand", `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*","Condition":{"Null":{"aws:SourceVpce":"maybe"}}}`,
			`statement 1: condition Null on aws:SourceVpce cannot compare with "maybe"`},
		{"user principal", principal("Allow", `{"AWS":"`+doorPrincipalArn+`"}`), `statement 1: Principal must be "*" or name AWS accounts; name users and roles with aws:PrincipalArn`},
		{"bad IP operand", `{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:VpcSourceIp":"10.0.0.0/33"}}}`,
			`statement 1: condition NotIpAddress on aws:VpcSourceIp cannot compare with "10.0.0.0/33"`},
		{"action pair", `{"Effect":"Allow","Principal":"*","Action":"*","NotAction":"s3:GetObject","Resource":"*"}`, "statement 1: a statement needs exactly one of Action and NotAction"},
		{"no action", `{"Effect":"Deny","Principal":"*","Resource":"*"}`, "statement 1: a statement needs exactly one of Action and NotAction"},
		{"no resource", `{"Effect":"Deny","Principal":"*","Action":"s3:*"}`, "statement 1: a statement needs exactly one of Resource and NotResource"},
		{"unresolvable variable in a condition", `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*",
			"Condition":{"StringEquals":{"aws:PrincipalArn":"${aws:PrincipalArn}"}}}`, "statement 1: condition StringEquals on aws:PrincipalArn has a policy variable that cannot be resolved"},
		{"unresolvable variable in a resource", `{"Effect":"Allow","Principal":"*","Action":"*","Resource":"arn:aws:s3:::${aws:SourceVpce}/*"}`,
			`statement 1: Resource "arn:aws:s3:::${aws:SourceVpce}/*" has a policy variable that cannot be resolved`},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			assert.EqualError(t, iampolicy.CheckEndpointPolicy(endpointDoc(t, iampolicy.Version2012, allowAll+","+tc.stmt)), tc.want)
		})
	}
}
