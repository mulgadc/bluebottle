package iampolicy_test

import (
	"maps"
	"testing"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two doors resolve overlapping-but-different context keys from the same
// request, so one policy document legitimately decides differently at each. The
// key sets here mirror the gateway's requestConditionKeys and predastore's
// conditionKeys; registry gates keep the copies honest.
const (
	doorAccount  = "111122223333"
	doorUser     = "alice"
	doorUserID   = "AIDAALICE"
	gatewayIP    = "10.1.2.3"
	s3GateIP     = "192.0.2.10"
	testResource = "arn:aws:s3:::reports"
	testAction   = "s3:ListBucket"
	// A role session's aws:userid is the role's ID and the session name, both
	// minted by STS: unlike aws:username it is not caller-chosen.
	doorSessionID = "AROASHAREDOPS:session"
	// The service an iam:PassRole check hands the role to.
	doorPassedTo = "ec2.amazonaws.com"
)

type door struct {
	name string
	keys iampolicy.ConditionKeys
}

var doors = []door{
	{"aws-gateway/user", iampolicy.ConditionKeys{
		iampolicy.KeySecureTransport:  "true",
		iampolicy.KeyUsername:         doorUser,
		iampolicy.KeyUserID:           doorUserID,
		iampolicy.KeyPrincipalAccount: doorAccount,
		iampolicy.KeySourceIP:         gatewayIP,
		iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeUser,
	}},
	// A role session has no aws:username at either door: the session name is
	// caller-chosen, so it cannot carry an authorization decision. aws:userid is
	// supplied, because STS mints it from the resolved role.
	{"aws-gateway/assumed-role", iampolicy.ConditionKeys{
		iampolicy.KeySecureTransport:  "true",
		iampolicy.KeyUserID:           doorSessionID,
		iampolicy.KeyPrincipalAccount: doorAccount,
		iampolicy.KeySourceIP:         gatewayIP,
		iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeAssumedRole,
	}},
	// An iam:PassRole check at the gateway carries the request's keys plus the
	// consuming service. No other action at either door supplies it.
	{"aws-gateway/passrole", iampolicy.ConditionKeys{
		iampolicy.KeySecureTransport:  "true",
		iampolicy.KeyUsername:         doorUser,
		iampolicy.KeyUserID:           doorUserID,
		iampolicy.KeyPrincipalAccount: doorAccount,
		iampolicy.KeySourceIP:         gatewayIP,
		iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeUser,
		iampolicy.KeyPassedToService:  doorPassedTo,
	}},
	{"s3-gate/user-listing", iampolicy.ConditionKeys{
		iampolicy.KeySecureTransport:  "true",
		iampolicy.KeyUsername:         doorUser,
		iampolicy.KeyUserID:           doorUserID,
		iampolicy.KeyPrincipalAccount: doorAccount,
		iampolicy.KeySourceIP:         s3GateIP,
		iampolicy.KeyS3Prefix:         "home/",
		iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeUser,
	}},
	{"s3-gate/user-object", iampolicy.ConditionKeys{
		iampolicy.KeySecureTransport:  "true",
		iampolicy.KeyUsername:         doorUser,
		iampolicy.KeyUserID:           doorUserID,
		iampolicy.KeyPrincipalAccount: doorAccount,
		iampolicy.KeySourceIP:         s3GateIP,
		iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeUser,
	}},
	{"s3-gate/role-session", iampolicy.ConditionKeys{
		iampolicy.KeySecureTransport:  "true",
		iampolicy.KeyUserID:           doorSessionID,
		iampolicy.KeyPrincipalAccount: doorAccount,
		iampolicy.KeySourceIP:         s3GateIP,
		iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeAssumedRole,
	}},
	{"s3-gate/user-object-plaintext", iampolicy.ConditionKeys{
		iampolicy.KeySecureTransport:  "false",
		iampolicy.KeyUsername:         doorUser,
		iampolicy.KeyUserID:           doorUserID,
		iampolicy.KeyPrincipalAccount: doorAccount,
		iampolicy.KeySourceIP:         s3GateIP,
		iampolicy.KeyPrincipalType:    iampolicy.PrincipalTypeUser,
	}},
}

// outcome is what a statement does at one door, held separately from its Effect
// so the same row pins both arms.
type outcome int

const (
	// inert: the statement selects nothing here. An Allow grants nothing and a
	// Deny takes nothing away — a supported key the door does not supply, or one
	// it supplies with a value the condition rejects.
	inert outcome = iota
	// failsClosed: the statement carries something this door cannot resolve, so
	// an Allow grants nothing and a Deny fires. The asymmetry is the point.
	failsClosed
	// grants: the statement selects the request. An Allow grants and a Deny fires.
	grants
)

func (o outcome) String() string {
	switch o {
	case inert:
		return "inert"
	case failsClosed:
		return "failsClosed"
	default:
		return "grants"
	}
}

type doorCase struct {
	name     string
	action   string
	resource string
	stmt     iampolicy.Statement
	want     map[string]outcome
}

// everywhere fills the expectation for all doors, so a row only spells out the
// doors that differ.
func everywhere(o outcome, except map[string]outcome) map[string]outcome {
	want := make(map[string]outcome, len(doors))
	for _, d := range doors {
		want[d.name] = o
	}
	maps.Copy(want, except)
	return want
}

func doorCases() []doorCase {
	cond := func(op, key string, values ...string) map[string]map[string]iampolicy.ConditionValue {
		return map[string]map[string]iampolicy.ConditionValue{op: {key: values}}
	}

	return []doorCase{
		{
			// Only the S3 gate supplies s3:prefix, and only for a listing.
			name: "s3:prefix StringEquals matches the listing prefix",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEquals, iampolicy.KeyS3Prefix, "home/")},
			want: everywhere(inert, map[string]outcome{"s3-gate/user-listing": grants}),
		},
		{
			name: "s3:prefix StringLike matches the listing prefix",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringLike, iampolicy.KeyS3Prefix, "home/*")},
			want: everywhere(inert, map[string]outcome{"s3-gate/user-listing": grants}),
		},
		{
			// Present-but-wrong is inert, not fail-closed: the door answered.
			name: "s3:prefix StringEquals a different prefix",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEquals, iampolicy.KeyS3Prefix, "other/")},
			want: everywhere(inert, nil),
		},
		{
			name: "aws:username condition",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEquals, iampolicy.KeyUsername, doorUser)},
			want: everywhere(grants, map[string]outcome{
				"aws-gateway/assumed-role": inert,
				"s3-gate/role-session":     inert,
			}),
		},
		{
			// The same key as a resource variable takes the other arm: a door that
			// cannot supply it fails closed rather than going inert. A Deny keyed
			// on aws:username in a condition is inert for a role session; written
			// as a variable it fires.
			name:     "aws:username as a resource variable",
			resource: testResource + "/alice/q.csv",
			stmt:     iampolicy.Statement{Resource: iampolicy.StringOrArr{testResource + "/${aws:username}/*"}},
			want: everywhere(grants, map[string]outcome{
				"aws-gateway/assumed-role": failsClosed,
				"s3-gate/role-session":     failsClosed,
			}),
		},
		{
			// Every door supplies aws:userid, so the pattern resolves everywhere
			// and the doors differ on the value rather than on its presence: a
			// role session's ID is not the user's, so it is inert, not fail-closed.
			name:     "aws:userid as a resource variable",
			resource: testResource + "/" + doorUserID + "/q.csv",
			stmt:     iampolicy.Statement{Resource: iampolicy.StringOrArr{testResource + "/${aws:userid}/*"}},
			want: everywhere(grants, map[string]outcome{
				"aws-gateway/assumed-role": inert,
				"s3-gate/role-session":     inert,
			}),
		},
		{
			// The same pattern against the session's own ID takes the other side.
			name:     "aws:userid as a resource variable, role session",
			resource: testResource + "/" + doorSessionID + "/q.csv",
			stmt:     iampolicy.Statement{Resource: iampolicy.StringOrArr{testResource + "/${aws:userid}/*"}},
			want: everywhere(inert, map[string]outcome{
				"aws-gateway/assumed-role": grants,
				"s3-gate/role-session":     grants,
			}),
		},
		{
			// The condition-value path fails closed the same way the resource
			// path does. The key is one no door can ever supply, so the row holds
			// whichever keys the doors gain.
			name: "unresolvable variable in a condition value",
			stmt: iampolicy.Statement{
				Condition: cond(iampolicy.OpStringEquals, iampolicy.KeyPrincipalAccount,
					"${aws:MultiFactorAuthPresent}"),
			},
			want: everywhere(failsClosed, nil),
		},
		{
			// The resource half of the same witness.
			name:     "unresolvable variable in a resource",
			resource: testResource + "/q.csv",
			stmt: iampolicy.Statement{
				Resource: iampolicy.StringOrArr{testResource + "/${aws:MultiFactorAuthPresent}/*"},
			},
			want: everywhere(failsClosed, nil),
		},
		{
			name: "aws:SecureTransport",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpBool, iampolicy.KeySecureTransport, "true")},
			want: everywhere(grants, map[string]outcome{"s3-gate/user-object-plaintext": inert}),
		},
		{
			name: "aws:SourceIp",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpIPAddress, iampolicy.KeySourceIP, "10.0.0.0/8")},
			want: everywhere(inert, map[string]outcome{
				"aws-gateway/user":         grants,
				"aws-gateway/assumed-role": grants,
				"aws-gateway/passrole":     grants,
			}),
		},
		{
			name: "aws:PrincipalAccount",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEquals, iampolicy.KeyPrincipalAccount, doorAccount)},
			want: everywhere(grants, nil),
		},
		{
			// Unlike aws:username, both doors supply aws:PrincipalType for every
			// principal type, so a role session is inert rather than absent: the
			// door answered "AssumedRole", which does not equal "User".
			name: "aws:PrincipalType StringEquals User",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEquals, iampolicy.KeyPrincipalType, iampolicy.PrincipalTypeUser)},
			want: everywhere(grants, map[string]outcome{
				"aws-gateway/assumed-role": inert,
				"s3-gate/role-session":     inert,
			}),
		},
		{
			name: "aws:PrincipalType StringLike AssumedRole",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringLike, iampolicy.KeyPrincipalType, "Assumed*")},
			want: everywhere(inert, map[string]outcome{
				"aws-gateway/assumed-role": grants,
				"s3-gate/role-session":     grants,
			}),
		},
		{
			name: "iam:PassedToService StringEquals the consuming service",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEquals, iampolicy.KeyPassedToService, doorPassedTo)},
			want: everywhere(inert, map[string]outcome{"aws-gateway/passrole": grants}),
		},
		{
			// A role passed to EC2 does not satisfy a grant scoped to ECS.
			name: "iam:PassedToService StringLike another service",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringLike, iampolicy.KeyPassedToService, "ecs-*")},
			want: everywhere(inert, nil),
		},
		{
			// Absent holds under a negated operator, so a role session — which has
			// no aws:username — satisfies it at both doors, as in AWS.
			name: "aws:username StringNotEquals another user",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringNotEquals, iampolicy.KeyUsername, "bob")},
			want: everywhere(grants, nil),
		},
		{
			// The user doors answer "alice" and the condition rejects it; the
			// role-session doors omit the key, so it holds there.
			name: "aws:username StringNotEquals the user",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringNotEquals, iampolicy.KeyUsername, doorUser)},
			want: everywhere(inert, map[string]outcome{
				"aws-gateway/assumed-role": grants,
				"s3-gate/role-session":     grants,
			}),
		},
		{
			// Only the listing supplies s3:prefix; every other door omits it.
			name: "s3:prefix StringNotLike the listing prefix",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringNotLike, iampolicy.KeyS3Prefix, "home/*")},
			want: everywhere(grants, map[string]outcome{"s3-gate/user-listing": inert}),
		},
		{
			// The "deny anything not from our network" idiom: the S3 gate's
			// address is outside the range, so the Deny fires there.
			name: "aws:SourceIp NotIpAddress",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpNotIPAddress, iampolicy.KeySourceIP, "10.0.0.0/8")},
			want: everywhere(grants, map[string]outcome{
				"aws-gateway/user":         inert,
				"aws-gateway/assumed-role": inert,
				"aws-gateway/passrole":     inert,
			}),
		},
		{
			name: "aws:PrincipalType StringEqualsIgnoreCase",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEqualsIgnoreCase, iampolicy.KeyPrincipalType, "assumedrole")},
			want: everywhere(inert, map[string]outcome{
				"aws-gateway/assumed-role": grants,
				"s3-gate/role-session":     grants,
			}),
		},
		{
			// Every action but PassRole omits the key, so a negated grant on it
			// reaches them too, as in AWS.
			name: "iam:PassedToService StringNotEquals the consuming service",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringNotEquals, iampolicy.KeyPassedToService, doorPassedTo)},
			want: everywhere(grants, map[string]outcome{"aws-gateway/passrole": inert}),
		},
		{
			// Role sessions carry no aws:username at either door.
			name: "aws:username Null true",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpNull, iampolicy.KeyUsername, "true")},
			want: everywhere(inert, map[string]outcome{
				"aws-gateway/assumed-role": grants,
				"s3-gate/role-session":     grants,
			}),
		},
		{
			name: "aws:username Null false",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpNull, iampolicy.KeyUsername, "false")},
			want: everywhere(grants, map[string]outcome{
				"aws-gateway/assumed-role": inert,
				"s3-gate/role-session":     inert,
			}),
		},
		{
			name: "s3:prefix Null false",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpNull, iampolicy.KeyS3Prefix, "false")},
			want: everywhere(inert, map[string]outcome{"s3-gate/user-listing": grants}),
		},
		{
			// Holds where the key is absent and compares where it is present, so
			// the role sessions and the user doors both grant.
			name: "aws:username StringEqualsIfExists the user",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEquals+iampolicy.IfExistsSuffix,
				iampolicy.KeyUsername, doorUser)},
			want: everywhere(grants, nil),
		},
		{
			name: "aws:username StringEqualsIfExists another user",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringEquals+iampolicy.IfExistsSuffix,
				iampolicy.KeyUsername, "bob")},
			want: everywhere(inert, map[string]outcome{
				"aws-gateway/assumed-role": grants,
				"s3-gate/role-session":     grants,
			}),
		},
		{
			name: "s3:prefix StringLikeIfExists another prefix",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringLike+iampolicy.IfExistsSuffix,
				iampolicy.KeyS3Prefix, "logs/*")},
			want: everywhere(grants, map[string]outcome{"s3-gate/user-listing": inert}),
		},
		{
			// Every door supplies the key, so the suffix changes nothing.
			name: "aws:SecureTransport BoolIfExists",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpBool+iampolicy.IfExistsSuffix,
				iampolicy.KeySecureTransport, "true")},
			want: everywhere(grants, map[string]outcome{"s3-gate/user-object-plaintext": inert}),
		},
		{
			name: "iam:PassedToService StringNotEqualsIfExists the consuming service",
			stmt: iampolicy.Statement{Condition: cond(iampolicy.OpStringNotEquals+iampolicy.IfExistsSuffix,
				iampolicy.KeyPassedToService, doorPassedTo)},
			want: everywhere(grants, map[string]outcome{"aws-gateway/passrole": inert}),
		},
		{
			// The key is present everywhere, so the suffix cannot rescue the
			// unresolvable value from failing closed.
			name: "unresolvable variable under IfExists",
			stmt: iampolicy.Statement{
				Condition: cond(iampolicy.OpStringEquals+iampolicy.IfExistsSuffix, iampolicy.KeyPrincipalAccount,
					"${aws:MultiFactorAuthPresent}"),
			},
			want: everywhere(failsClosed, nil),
		},
		{
			name: "NotAction excluding another action",
			stmt: iampolicy.Statement{NotAction: iampolicy.StringOrArr{"s3:DeleteObject"}},
			want: everywhere(grants, nil),
		},
		{
			name: "NotAction excluding the requested action",
			stmt: iampolicy.Statement{NotAction: iampolicy.StringOrArr{"s3:List*"}},
			want: everywhere(inert, nil),
		},
		{
			name: "NotResource excluding another resource",
			stmt: iampolicy.Statement{NotResource: iampolicy.StringOrArr{testResource + "-archive"}},
			want: everywhere(grants, nil),
		},
		{
			name: "NotResource excluding the requested resource",
			stmt: iampolicy.Statement{NotResource: iampolicy.StringOrArr{testResource}},
			want: everywhere(inert, nil),
		},
		{
			// The inverse of the resource-variable row: resolved, the exclusion
			// removes the user's own prefix; unresolved, it fails closed.
			name:     "aws:username as a NotResource variable",
			resource: testResource + "/alice/q.csv",
			stmt:     iampolicy.Statement{NotResource: iampolicy.StringOrArr{testResource + "/${aws:username}/*"}},
			want: everywhere(inert, map[string]outcome{
				"aws-gateway/assumed-role": failsClosed,
				"s3-gate/role-session":     failsClosed,
			}),
		},
		{
			// A key no door can ever supply is unenforceable, not merely absent,
			// so it fails closed everywhere.
			name: "condition on an unsupported key",
			stmt: iampolicy.Statement{
				Condition: cond(iampolicy.OpBool, "aws:MultiFactorAuthPresent", "true"),
			},
			want: everywhere(failsClosed, nil),
		},
	}
}

// Each document is evaluated at every door in both effects. The Allow arm is
// evaluated alone; the Deny arm sits alongside an unconditional Allow, so a Deny
// that failed to fire shows up as an Allow rather than as the ambient deny.
func TestEvaluate_DoorsResolveTheSameDocument(t *testing.T) {
	for _, tc := range doorCases() {
		for _, d := range doors {
			t.Run(tc.name+"/"+d.name, func(t *testing.T) {
				want, ok := tc.want[d.name]
				require.True(t, ok, "case %q has no expectation for door %q", tc.name, d.name)

				action, resource := tc.action, tc.resource
				if action == "" {
					action = testAction
				}
				if resource == "" {
					resource = testResource
				}

				allowed := iampolicy.EvaluateWithKeys(action, resource,
					[]iampolicy.PolicyDocument{{Statement: []iampolicy.Statement{
						effected(tc.stmt, iampolicy.EffectAllow),
					}}}, d.keys)

				denied := iampolicy.EvaluateWithKeys(action, resource,
					[]iampolicy.PolicyDocument{
						{Statement: []iampolicy.Statement{effected(tc.stmt, iampolicy.EffectDeny)}},
						{Statement: []iampolicy.Statement{stmt("Allow", "s3:*", "*")}},
					}, d.keys)

				assert.Equal(t, want == grants, allowed == iampolicy.Allow,
					"Allow arm at %s: want %s", d.name, want)
				assert.Equal(t, want != inert, denied == iampolicy.Deny,
					"Deny arm at %s: want %s", d.name, want)

				// The relation the doors must preserve however the keys differ: a
				// statement that grants as an Allow must fire as a Deny, so no
				// document can be more permissive in its restrictive form.
				if allowed == iampolicy.Allow {
					assert.Equal(t, iampolicy.Deny, denied,
						"%s grants as an Allow but does not fire as a Deny at %s", tc.name, d.name)
				}
			})
		}
	}
}

// effected fills in the Effect and the selectors a row left blank, so each case
// only writes the construct under test.
func effected(s iampolicy.Statement, effect string) iampolicy.Statement {
	s.Effect = effect
	if len(s.Action) == 0 && len(s.NotAction) == 0 {
		s.Action = iampolicy.StringOrArr{"s3:*"}
	}
	if len(s.Resource) == 0 && len(s.NotResource) == 0 {
		s.Resource = iampolicy.StringOrArr{"*"}
	}
	return s
}

// The S3 gate resolves everything the AWS gateway does for the same principal,
// plus s3:prefix on a listing. A key added at one door and not the other shows
// up here.
func TestDoors_S3GateSuppliesASupersetOfTheGatewayKeys(t *testing.T) {
	byName := make(map[string]iampolicy.ConditionKeys, len(doors))
	for _, d := range doors {
		byName[d.name] = d.keys
	}

	pairs := []struct{ gateway, s3 string }{
		{"aws-gateway/user", "s3-gate/user-object"},
		{"aws-gateway/user", "s3-gate/user-listing"},
		{"aws-gateway/assumed-role", "s3-gate/role-session"},
	}
	for _, p := range pairs {
		for key := range byName[p.gateway] {
			assert.Contains(t, byName[p.s3], key,
				"%s supplies %s but %s does not", p.gateway, key, p.s3)
		}
	}

	assert.NotContains(t, byName["aws-gateway/user"], iampolicy.KeyS3Prefix,
		"s3:prefix has no meaning on the AWS API path")
	assert.Contains(t, byName["s3-gate/user-listing"], iampolicy.KeyS3Prefix)
}
