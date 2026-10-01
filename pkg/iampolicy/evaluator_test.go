package iampolicy_test

import (
	"encoding/json"
	"testing"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// doc builds a single-statement policy document.
func doc(effect, action, resource string) iampolicy.PolicyDocument {
	return iampolicy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []iampolicy.Statement{
			{Effect: effect, Action: iampolicy.StringOrArr{action}, Resource: iampolicy.StringOrArr{resource}},
		},
	}
}

func TestEvaluate_DefaultDeny(t *testing.T) {
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", nil, nil))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", []iampolicy.PolicyDocument{}, nil))
}

func TestEvaluate_ExplicitAllow(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "ec2:RunInstances", "*")}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", p, nil))
}

func TestEvaluate_ExplicitDenyWins(t *testing.T) {
	// Deny in a separate document overrides an Allow.
	p := []iampolicy.PolicyDocument{
		doc("Allow", "ec2:*", "*"),
		doc("Deny", "ec2:TerminateInstances", "*"),
	}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("ec2:TerminateInstances", "*", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", p, nil))
}

func TestEvaluate_ExplicitDenyWinsSamePolicy(t *testing.T) {
	p := []iampolicy.PolicyDocument{{
		Version: "2012-10-17",
		Statement: []iampolicy.Statement{
			{Effect: "Allow", Action: iampolicy.StringOrArr{"ec2:*"}, Resource: iampolicy.StringOrArr{"*"}},
			{Effect: "Deny", Action: iampolicy.StringOrArr{"ec2:TerminateInstances"}, Resource: iampolicy.StringOrArr{"*"}},
		},
	}}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("ec2:TerminateInstances", "*", p, nil))
}

// A Deny whose Resource uses the single-character wildcard must fire. Treating
// "?" as a literal made the Deny miss and the broad Allow win.
func TestEvaluate_DenySingleCharacterWildcard(t *testing.T) {
	p := []iampolicy.PolicyDocument{
		doc("Allow", "s3:*", "arn:aws:s3:::*"),
		doc("Deny", "s3:*", "arn:aws:s3:::secret?/*"),
	}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::secrets/object", p, nil))
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::secret/object", p, nil))
}

func TestEvaluate_NoMatchingAction(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "*")}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", p, nil))
}

func TestEvaluate_Wildcards(t *testing.T) {
	tests := []struct {
		name   string
		policy iampolicy.PolicyDocument
		action string
		want   iampolicy.Decision
	}{
		{"all", doc("Allow", "*", "*"), "ec2:RunInstances", iampolicy.Allow},
		{"service-hit", doc("Allow", "ec2:*", "*"), "ec2:DescribeInstances", iampolicy.Allow},
		{"service-miss", doc("Allow", "ec2:*", "*"), "s3:GetObject", iampolicy.Deny},
		{"prefix-hit", doc("Allow", "s3:Get*", "*"), "s3:GetBucketPolicy", iampolicy.Allow},
		{"prefix-miss", doc("Allow", "s3:Get*", "*"), "s3:PutObject", iampolicy.Deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := iampolicy.EvaluateWithKeys(tt.action, "*", []iampolicy.PolicyDocument{tt.policy}, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEvaluate_CaseInsensitiveAction(t *testing.T) {
	// Actions match case-insensitively per AWS spec.
	p := []iampolicy.PolicyDocument{doc("Allow", "EC2:RunInstances", "*")}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", p, nil))
	p2 := []iampolicy.PolicyDocument{doc("Allow", "s3:getobject", "*")}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "*", p2, nil))
}

func TestEvaluate_CaseSensitiveResource(t *testing.T) {
	// Resource ARNs match case-sensitively per AWS spec — this is the unified
	// behaviour (predastore always did this; spinifex now does too).
	p := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::MyBucket/*")}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::MyBucket/key", p, nil),
		"exact-case resource must match")
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::mybucket/key", p, nil),
		"differing-case resource must NOT match")
}

func TestEvaluate_ResourceScoped(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::my-bucket/*")}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::my-bucket/k.txt", p, nil))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::other/k.txt", p, nil))
}

func TestEvaluate_UnknownEffectFailsClosed(t *testing.T) {
	// An unrecognized Effect fails closed to Deny, even alongside a real Allow.
	p := []iampolicy.PolicyDocument{
		doc("Allow", "s3:GetObject", "*"),
		doc("Sideways", "s3:GetObject", "*"),
	}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "*", p, nil),
		"unknown Effect on a matching statement must Deny")

	// A non-matching unknown-Effect statement is inert (never reached).
	p2 := []iampolicy.PolicyDocument{
		doc("Allow", "s3:GetObject", "*"),
		doc("Bogus", "ec2:RunInstances", "*"),
	}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "*", p2, nil))
}

func TestEvaluate_MultipleActionsAndPolicies(t *testing.T) {
	p := []iampolicy.PolicyDocument{
		{Version: "2012-10-17", Statement: []iampolicy.Statement{{
			Effect:   "Allow",
			Action:   iampolicy.StringOrArr{"ec2:DescribeInstances", "ec2:RunInstances"},
			Resource: iampolicy.StringOrArr{"*"},
		}}},
		doc("Allow", "s3:GetObject", "*"),
	}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "*", p, nil))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("iam:CreateUser", "*", p, nil))
}

// TestEvaluate_PassRoleResourceARN exercises the infix resource-ARN path used by
// iam:PassRole enforcement.
func TestEvaluate_PassRoleResourceARN(t *testing.T) {
	p := []iampolicy.PolicyDocument{
		doc("Allow", "iam:PassRole", "arn:aws:iam::*:role/app-*"),
	}
	tests := []struct {
		resource string
		want     iampolicy.Decision
	}{
		{"arn:aws:iam::123456789012:role/app-foo", iampolicy.Allow},
		{"arn:aws:iam::999999999999:role/app-bar", iampolicy.Allow},
		{"arn:aws:iam::123456789012:role/admin-foo", iampolicy.Deny},
		{"arn:aws:iam::123456789012:user/app-foo", iampolicy.Deny},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, iampolicy.EvaluateWithKeys("iam:PassRole", tt.resource, p, nil), "PassRole on %s", tt.resource)
	}
}

// With no context keys a conditional Allow cannot fire — the original bug's
// reproduction case.
func TestEvaluate_ConditionalAllowDeniedWithoutKeys(t *testing.T) {
	d := doc("Allow", "*", "*")
	d.Statement[0].Sid = "OfficeOnly"
	d.Statement[0].Condition = map[string]map[string]iampolicy.ConditionValue{
		"IpAddress": {"aws:SourceIp": {"10.0.0.0/8"}},
	}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("ec2:TerminateInstances", "*", []iampolicy.PolicyDocument{d}, nil))
}

// A Deny carrying an unenforceable condition fires regardless: dropping it would
// be the only fail-open direction available.
func TestEvaluate_UnenforceableDenyStillDenies(t *testing.T) {
	allow := doc("Allow", "*", "*")
	deny := doc("Deny", "ec2:TerminateInstances", "*")
	deny.Statement[0].Condition = unenforceableCondition
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("ec2:TerminateInstances", "*", []iampolicy.PolicyDocument{allow, deny}, nil))
}

func TestEvaluate_NotActionAlongsideActionFailsClosed(t *testing.T) {
	d := doc("Allow", "s3:*", "*")
	d.Statement[0].NotAction = iampolicy.StringOrArr{"s3:DeleteObject"}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "*", []iampolicy.PolicyDocument{d}, nil))

	// Read as either selector alone, this Deny would spare s3:GetObject.
	deny := doc("Deny", "ec2:*", "*")
	deny.Statement[0].NotAction = iampolicy.StringOrArr{"s3:GetObject"}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "*",
			[]iampolicy.PolicyDocument{doc("Allow", "*", "*"), deny}, nil))
}

func TestEvaluate_NotResourceAlongsideResourceFailsClosed(t *testing.T) {
	allow := doc("Allow", "s3:*", "*")
	allow.Statement[0].NotResource = iampolicy.StringOrArr{"arn:aws:s3:::private/*"}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::public/a", []iampolicy.PolicyDocument{allow}, nil))

	deny := doc("Deny", "s3:*", "arn:aws:s3:::nothing")
	deny.Statement[0].NotResource = iampolicy.StringOrArr{"arn:aws:s3:::public/*"}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::public/a",
			[]iampolicy.PolicyDocument{doc("Allow", "*", "*"), deny}, nil))
}

// A well-formed Not selector on a Deny that fails closed for another reason
// still selects its complement; it must not collapse to selecting nothing.
func TestEvaluate_UnenforceableDenyKeepsNotSelectors(t *testing.T) {
	notAction := notActionDoc("Deny", "s3:Get*")
	notAction.Statement[0].Condition = unenforceableCondition
	p := []iampolicy.PolicyDocument{doc("Allow", "*", "*"), notAction}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "*", p, nil))

	notResource := notResourceDoc("Deny", "arn:aws:s3:::public/*")
	notResource.Statement[0].Condition = unenforceableCondition
	p = []iampolicy.PolicyDocument{doc("Allow", "*", "*"), notResource}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::private/a", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::public/a", p, nil))
}

func notActionDoc(effect string, notAction ...string) iampolicy.PolicyDocument {
	return iampolicy.PolicyDocument{Version: iampolicy.Version2012, Statement: []iampolicy.Statement{{
		Effect:    effect,
		NotAction: notAction,
		Resource:  iampolicy.StringOrArr{"*"},
	}}}
}

func notResourceDoc(effect string, notResource ...string) iampolicy.PolicyDocument {
	return iampolicy.PolicyDocument{Version: iampolicy.Version2012, Statement: []iampolicy.Statement{{
		Effect:      effect,
		Action:      iampolicy.StringOrArr{"s3:*"},
		NotResource: notResource,
	}}}
}

// The PowerUserAccess shape: everything except IAM.
func TestEvaluate_AllowNotActionGrantsTheComplement(t *testing.T) {
	p := []iampolicy.PolicyDocument{notActionDoc("Allow", "iam:*", "organizations:DescribeOrganization")}

	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("organizations:ListAccounts", "*", p, nil))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("iam:CreateUser", "*", p, nil))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("organizations:DescribeOrganization", "*", p, nil))
	// Actions match case-insensitively on the excluded side too.
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("IAM:CreateUser", "*", p, nil))
}

func TestEvaluate_DenyNotActionDeniesTheComplement(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "*", "*"), notActionDoc("Deny", "sts:AssumeRole", "s3:Get*")}

	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("ec2:DescribeInstances", "*", p, nil))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:PutObject", "*", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("sts:AssumeRole", "*", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "*", p, nil))
}

func TestEvaluate_AllowNotResourceGrantsTheComplement(t *testing.T) {
	p := []iampolicy.PolicyDocument{notResourceDoc("Allow", "arn:aws:s3:::secret", "arn:aws:s3:::secret/*")}

	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::public/a", p, nil))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::secret/a", p, nil))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:ListBucket", "arn:aws:s3:::secret", p, nil))
	// Resources match case-sensitively, so a differently-cased ARN is not excluded.
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::SECRET/a", p, nil))
	// The action selector still applies.
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("ec2:RunInstances", "arn:aws:s3:::public/a", p, nil))
}

func TestEvaluate_DenyNotResourceDeniesTheComplement(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "*", "*"), notResourceDoc("Deny", "arn:aws:s3:::public/*")}

	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::private/a", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::public/a", p, nil))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("ec2:RunInstances", "arn:aws:s3:::private/a", p, nil))
}

// A NotResource carrying a variable excludes the principal's own prefix once
// resolved, and only narrows access when it cannot be.
func TestEvaluate_NotResourceWithPolicyVariable(t *testing.T) {
	const own = "arn:aws:s3:::home/alice/a"
	const other = "arn:aws:s3:::home/bob/a"
	alice := iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}
	role := iampolicy.ConditionKeys{iampolicy.KeyUserID: "AROAROLE:session"}

	allow := []iampolicy.PolicyDocument{notResourceDoc("Allow", "arn:aws:s3:::home/${aws:username}/*")}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", other, allow, alice))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", own, allow, alice))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", other, allow, role),
		"an unresolvable exclusion must not widen an Allow")

	deny := []iampolicy.PolicyDocument{doc("Allow", "*", "*"), notResourceDoc("Deny", "arn:aws:s3:::home/${aws:username}/*")}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", other, deny, alice))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", own, deny, alice))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", own, deny, role),
		"an unresolvable exclusion must not narrow a Deny")
}

// A resource-policy document evaluated as an identity policy must not grant:
// Principal is not enforced here, so an Allow carrying one fails closed.
func TestEvaluate_PrincipalAllowFailsClosed(t *testing.T) {
	d := doc("Allow", "s3:*", "*")
	d.Statement[0].Principal = json.RawMessage(`{"AWS":"arn:aws:iam::999999999999:root"}`)
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "*", []iampolicy.PolicyDocument{d}, nil))
}

// The same statement as a Deny still fires, so an unenforced Principal can only
// narrow access.
func TestEvaluate_PrincipalDenyStillDenies(t *testing.T) {
	allow := doc("Allow", "*", "*")
	deny := doc("Deny", "s3:*", "*")
	deny.Statement[0].Principal = json.RawMessage(`{"AWS":"arn:aws:iam::999999999999:root"}`)
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "*", []iampolicy.PolicyDocument{allow, deny}, nil))
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("ec2:DescribeInstances", "*", []iampolicy.PolicyDocument{allow, deny}, nil))
}

// A spelled-out null Principal is absent, not a construct to fail closed on.
func TestEvaluate_NullPrincipalStillAllows(t *testing.T) {
	d := doc("Allow", "s3:*", "*")
	d.Statement[0].Principal = json.RawMessage(`null`)
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "*", []iampolicy.PolicyDocument{d}, nil))
}

// The document as it arrives over the wire takes the same path.
func TestEvaluate_PrincipalFromJSONFailsClosed(t *testing.T) {
	var d iampolicy.PolicyDocument
	require.NoError(t, json.Unmarshal([]byte(`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},
		 "Action":"s3:*","Resource":"*"}]}`), &d))
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "*", []iampolicy.PolicyDocument{d}, nil))
}

// An unenforceable Deny still has to select the action to fire.
func TestEvaluate_UnenforceableDenyStillScopedByAction(t *testing.T) {
	allow := doc("Allow", "*", "*")
	deny := doc("Deny", "s3:DeleteObject", "*")
	deny.Statement[0].Condition = unenforceableCondition
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("ec2:DescribeInstances", "*", []iampolicy.PolicyDocument{allow, deny}, nil))
}

// The per-user prefix idiom end to end: without substitution the Allow never
// fires.
func TestEvaluate_PerUserPrefixVariable(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::home/${aws:username}/*")}
	alice := iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}

	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/alice/object", p, alice))
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/bob/object", p, alice))
}

// An unsuppliable key makes the statement non-matching rather than substituting
// empty, which would select a different set of resources.
func TestEvaluate_UnresolvableVariableDoesNotMatch(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::home/${aws:username}/*")}

	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/alice/object", p, nil))
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home//object", p, nil))
}

// A Deny fails the other way: an unsuppliable key makes it match, so the
// restriction survives a door that cannot resolve it. Doors omit aws:username
// for assumed-role sessions, so the alternative is a Deny that is silently inert
// for every role.
func TestEvaluate_UnresolvableVariableOnDeny(t *testing.T) {
	p := []iampolicy.PolicyDocument{
		doc("Allow", "s3:*", "arn:aws:s3:::*"),
		doc("Deny", "s3:*", "arn:aws:s3:::home/${aws:username}/*"),
	}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject",
		"arn:aws:s3:::home/alice/object", p, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}))
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/alice/object", p, nil))

	// Failing closed is scoped by Action: it does not turn the Deny into a
	// blanket one over services it never named.
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("ec2:DescribeInstances", "arn:aws:s3:::home/alice/object",
			[]iampolicy.PolicyDocument{
				doc("Allow", "ec2:*", "arn:aws:s3:::*"),
				doc("Deny", "s3:*", "arn:aws:s3:::home/${aws:username}/*"),
			}, nil))

	// A resolvable Deny is unaffected: it still only covers what it names.
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject",
		"arn:aws:s3:::home/bob/object", p, iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}))
}

// The same rule for a variable in a Deny's condition value: unresolvable means
// the condition holds, so the Deny fires rather than evaporating.
func TestEvaluate_UnresolvableVariableInDenyCondition(t *testing.T) {
	deny := doc("Deny", "s3:*", "arn:aws:s3:::bucket/*")
	deny.Statement[0].Condition = map[string]map[string]iampolicy.ConditionValue{
		"StringLike": {"s3:prefix": {"${aws:username}/*"}},
	}
	p := []iampolicy.PolicyDocument{doc("Allow", "s3:*", "arn:aws:s3:::*"), deny}
	keys := iampolicy.ConditionKeys{iampolicy.KeyS3Prefix: "alice/x"}

	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::bucket/x", p, keys))

	// With the key suppliable it resolves normally, and a non-matching prefix
	// leaves the Allow standing.
	keys[iampolicy.KeyUsername] = "bob"
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::bucket/x", p, keys))
}

// A metacharacter in a principal attribute must not become a wildcard, or a
// user named "*" would reach every other user's prefix.
func TestEvaluate_SubstitutedWildcardDoesNotEscalate(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::home/${aws:username}/*")}
	star := iampolicy.ConditionKeys{iampolicy.KeyUsername: "*"}

	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/alice/object", p, star))
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/*/object", p, star))

	q := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::home/${aws:username}/*")}
	single := iampolicy.ConditionKeys{iampolicy.KeyUsername: "?"}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/a/object", q, single))
}

// Single pass: an attribute that looks like a reference stays literal text.
func TestEvaluate_SubstitutedValueIsNotReexpanded(t *testing.T) {
	p := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::home/${aws:username}/*")}
	keys := iampolicy.ConditionKeys{
		iampolicy.KeyUsername: "${aws:PrincipalAccount}", iampolicy.KeyPrincipalAccount: "000000000001",
	}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/000000000001/object", p, keys))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject",
		"arn:aws:s3:::home/${aws:PrincipalAccount}/object", p, keys))
}

// The keys identifying the caller other than aws:username, which the per-user
// prefix cases above cover.
func TestEvaluate_AccountAndUserIDVariables(t *testing.T) {
	keys := iampolicy.ConditionKeys{
		iampolicy.KeyPrincipalAccount: "000000000001", iampolicy.KeyUserID: "AIDAALICE",
	}
	account := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::${aws:PrincipalAccount}/*")}
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::000000000001/k", account, keys))

	userID := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", "arn:aws:s3:::u/${aws:userid}/*")}
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::u/AIDAALICE/k", userID, keys))
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::u/AIDABOB/k", userID, keys))

	// A door that cannot supply the ID makes the pattern select nothing on an
	// Allow, and everything it names on a Deny.
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject",
		"arn:aws:s3:::u/AIDAALICE/k", userID, iampolicy.ConditionKeys{}))

	denyUserID := []iampolicy.PolicyDocument{doc("Deny", "s3:GetObject", "arn:aws:s3:::u/${aws:userid}/*")}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject",
		"arn:aws:s3:::u/bob/k", denyUserID, iampolicy.ConditionKeys{}))
}

// Under 2008-10-17, and with Version omitted, ${...} is literal text as in AWS,
// while the rest of the pattern keeps its wildcards.
func TestEvaluate_LegacyVersionTreatsVariablesAsLiterals(t *testing.T) {
	alice := iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}
	const pattern = "arn:aws:s3:::home/${aws:username}/*"

	for _, version := range []string{iampolicy.Version2008, ""} {
		p := doc("Allow", "s3:GetObject", pattern)
		p.Version = version
		policies := []iampolicy.PolicyDocument{p}

		assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/alice/a", policies, alice),
			"version %q must not resolve the variable", version)
		assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/${aws:username}/a", policies, alice),
			"version %q must match the literal text", version)
		assert.Equal(t, pattern, policies[0].Statement[0].Resource[0], "the caller's document must not be rewritten")
	}

	current := []iampolicy.PolicyDocument{doc("Allow", "s3:GetObject", pattern)}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/alice/a", current, alice))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/${aws:username}/a", current, alice))
}

// A legacy-version reference to a key no door supplies is literal text, so it
// neither fails closed on an Allow nor on a Deny.
func TestEvaluate_LegacyVersionUnknownVariableIsLiteral(t *testing.T) {
	allow := doc("Allow", "s3:GetObject", "arn:aws:s3:::${unknown}/*")
	allow.Version = iampolicy.Version2008
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::${unknown}/a",
		[]iampolicy.PolicyDocument{allow}, nil))

	deny := doc("Deny", "s3:GetObject", "arn:aws:s3:::${unknown}/*")
	deny.Version = iampolicy.Version2008
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::other/a",
		[]iampolicy.PolicyDocument{doc("Allow", "s3:*", "*"), deny}, nil))
}

// Condition values in a legacy-version document compare ${...} literally.
func TestEvaluate_LegacyVersionConditionValueIsLiteral(t *testing.T) {
	p := doc("Allow", "s3:ListBucket", "*")
	p.Version = iampolicy.Version2008
	p.Statement[0].Condition = map[string]map[string]iampolicy.ConditionValue{
		iampolicy.OpStringLike: {iampolicy.KeyS3Prefix: {"home/${aws:username}/*"}},
	}
	policies := []iampolicy.PolicyDocument{p}

	resolved := iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice", iampolicy.KeyS3Prefix: "home/alice/x"}
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:ListBucket", "*", policies, resolved))

	literal := iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice", iampolicy.KeyS3Prefix: "home/${aws:username}/x"}
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:ListBucket", "*", policies, literal))
	assert.Equal(t, "home/${aws:username}/*", p.Statement[0].Condition[iampolicy.OpStringLike][iampolicy.KeyS3Prefix][0],
		"the caller's condition must not be rewritten")
}

// A legacy-version document keeps its statements without ${...} untouched beside
// the ones it rewrites.
func TestEvaluate_LegacyVersionKeepsEveryStatement(t *testing.T) {
	alice := iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}
	p := iampolicy.PolicyDocument{Version: iampolicy.Version2008, Statement: []iampolicy.Statement{
		doc("Deny", "s3:DeleteObject", "*").Statement[0],
		doc("Allow", "s3:*", "arn:aws:s3:::home/${aws:username}/*").Statement[0],
	}}
	policies := []iampolicy.PolicyDocument{p}
	const literal = "arn:aws:s3:::home/${aws:username}/a"

	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:DeleteObject", literal, policies, alice))
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", literal, policies, alice))
	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/alice/a", policies, alice))
}

// A legacy-version NotResource is literal text too.
func TestEvaluate_LegacyVersionNotResourceIsLiteral(t *testing.T) {
	alice := iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}
	deny := notResourceDoc("Deny", "arn:aws:s3:::home/${aws:username}/*")
	deny.Statement[0].Action = iampolicy.StringOrArr{"s3:GetObject"}
	deny.Version = iampolicy.Version2008
	allow := doc("Allow", "s3:GetObject", "arn:aws:s3:::home/${aws:username}/*")
	policies := []iampolicy.PolicyDocument{deny, allow}

	assert.Equal(t, iampolicy.Deny, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/alice/a", policies, alice),
		"the 2008 NotResource must not resolve, so home/alice is outside it and denied")
	assert.Equal(t, "arn:aws:s3:::home/${aws:username}/*", deny.Statement[0].NotResource[0])

	allowLiteral := doc("Allow", "s3:GetObject", "arn:aws:s3:::home/*")
	assert.Equal(t, iampolicy.Allow, iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::home/${aws:username}/a",
		[]iampolicy.PolicyDocument{deny, allowLiteral}, alice), "the literal path is inside the 2008 NotResource")
}
