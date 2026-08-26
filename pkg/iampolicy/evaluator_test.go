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
	deny.Statement[0].Condition = map[string]map[string]iampolicy.ConditionValue{
		"DateGreaterThan": {"aws:CurrentTime": {"2020-01-01T00:00:00Z"}},
	}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("ec2:TerminateInstances", "*", []iampolicy.PolicyDocument{allow, deny}, nil))
}

func TestEvaluate_NotActionAlongsideActionFailsClosed(t *testing.T) {
	d := doc("Allow", "s3:*", "*")
	d.Statement[0].NotAction = iampolicy.StringOrArr{"s3:DeleteObject"}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "*", []iampolicy.PolicyDocument{d}, nil))
}

// A Deny whose only selector is NotAction is inert today and denies everything
// under the fail-closed rule. Pinned so the behaviour change cannot regress.
func TestEvaluate_NotActionOnlyDenyMatchesEverything(t *testing.T) {
	allow := doc("Allow", "*", "*")
	deny := iampolicy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []iampolicy.Statement{{
			Effect:    "Deny",
			NotAction: iampolicy.StringOrArr{"sts:AssumeRole"},
			Resource:  iampolicy.StringOrArr{"*"},
		}},
	}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("sts:AssumeRole", "*", []iampolicy.PolicyDocument{allow, deny}, nil))
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("ec2:DescribeInstances", "*", []iampolicy.PolicyDocument{allow, deny}, nil))
}

func TestEvaluate_NotResourceOnlyDenyMatchesEverything(t *testing.T) {
	allow := doc("Allow", "*", "*")
	deny := iampolicy.PolicyDocument{
		Version: "2012-10-17",
		Statement: []iampolicy.Statement{{
			Effect:      "Deny",
			Action:      iampolicy.StringOrArr{"s3:*"},
			NotResource: iampolicy.StringOrArr{"arn:aws:s3:::public/*"},
		}},
	}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::public/a", []iampolicy.PolicyDocument{allow, deny}, nil))
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
	deny.Statement[0].Condition = map[string]map[string]iampolicy.ConditionValue{
		"DateGreaterThan": {"aws:CurrentTime": {"2020-01-01T00:00:00Z"}},
	}
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("ec2:DescribeInstances", "*", []iampolicy.PolicyDocument{allow, deny}, nil))
}
