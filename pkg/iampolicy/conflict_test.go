package iampolicy_test

import (
	"testing"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
)

// policySources are the resolution origins a principal's grants arrive from, in
// the order spinifex concatenates them into the document slice. The evaluator
// flattens the slice, so no origin may be privileged over another.
var policySources = []string{
	"user-managed", "user-inline",
	"group-managed", "group-inline",
	"role-managed", "role-inline",
}

// sourceSlice builds one document per source, empty except where at names a
// statement — a principal whose grants come from several places at once.
func sourceSlice(at map[string]iampolicy.Statement) []iampolicy.PolicyDocument {
	docs := make([]iampolicy.PolicyDocument, 0, len(policySources))
	for _, src := range policySources {
		d := iampolicy.PolicyDocument{Version: "2012-10-17"}
		if s, ok := at[src]; ok {
			s.Sid = src
			d.Statement = []iampolicy.Statement{s}
		}
		docs = append(docs, d)
	}
	return docs
}

func stmt(effect, action, resource string) iampolicy.Statement {
	return iampolicy.Statement{
		Effect:   effect,
		Action:   iampolicy.StringOrArr{action},
		Resource: iampolicy.StringOrArr{resource},
	}
}

// An explicit Deny must override an Allow from any other source, in both slice
// orders — the grid covers each ordered pair, so a resolution order that let an
// earlier Allow win would fail half the cells.
func TestEvaluate_ExplicitDenyWinsAcrossEverySourcePair(t *testing.T) {
	for _, allowSrc := range policySources {
		for _, denySrc := range policySources {
			if allowSrc == denySrc {
				continue
			}
			t.Run("allow_"+allowSrc+"/deny_"+denySrc, func(t *testing.T) {
				docs := sourceSlice(map[string]iampolicy.Statement{
					allowSrc: stmt("Allow", "ec2:*", "*"),
					denySrc:  stmt("Deny", "ec2:TerminateInstances", "*"),
				})
				assert.Equal(t, iampolicy.Deny,
					iampolicy.EvaluateWithKeys("ec2:TerminateInstances", "*", docs, nil),
					"Deny in %s must override Allow in %s", denySrc, allowSrc)
				assert.Equal(t, iampolicy.Allow,
					iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", docs, nil),
					"Deny in %s must not narrow an unrelated action", denySrc)
			})
		}
	}
}

// The same crossing with resource scoping: the Deny names one ARN and must take
// only that one out of a broad Allow held in a different source.
func TestEvaluate_ResourceScopedDenyAcrossEverySourcePair(t *testing.T) {
	const (
		fleet   = "arn:aws:ec2:ap-southeast-2:111122223333:instance/*"
		guarded = "arn:aws:ec2:ap-southeast-2:111122223333:instance/i-guarded"
		other   = "arn:aws:ec2:ap-southeast-2:111122223333:instance/i-other"
	)
	for _, allowSrc := range policySources {
		for _, denySrc := range policySources {
			if allowSrc == denySrc {
				continue
			}
			t.Run("allow_"+allowSrc+"/deny_"+denySrc, func(t *testing.T) {
				docs := sourceSlice(map[string]iampolicy.Statement{
					allowSrc: stmt("Allow", "ec2:StopInstances", fleet),
					denySrc:  stmt("Deny", "ec2:StopInstances", guarded),
				})
				assert.Equal(t, iampolicy.Deny,
					iampolicy.EvaluateWithKeys("ec2:StopInstances", guarded, docs, nil))
				assert.Equal(t, iampolicy.Allow,
					iampolicy.EvaluateWithKeys("ec2:StopInstances", other, docs, nil))
			})
		}
	}
}

// Slice order must not decide the outcome: the loop returns on the first Deny,
// so a Deny reached after the matching Allow has to win just the same.
func TestEvaluate_DenyWinsRegardlessOfOrder(t *testing.T) {
	allow := stmt("Allow", "ec2:*", "*")
	deny := stmt("Deny", "ec2:TerminateInstances", "*")

	acrossDocs := func(first, second iampolicy.Statement) []iampolicy.PolicyDocument {
		return []iampolicy.PolicyDocument{
			{Version: "2012-10-17", Statement: []iampolicy.Statement{first}},
			{Version: "2012-10-17", Statement: []iampolicy.Statement{second}},
		}
	}
	withinDoc := func(first, second iampolicy.Statement) []iampolicy.PolicyDocument {
		return []iampolicy.PolicyDocument{
			{Version: "2012-10-17", Statement: []iampolicy.Statement{first, second}},
		}
	}

	cases := map[string][]iampolicy.PolicyDocument{
		"deny after allow, separate documents":  acrossDocs(allow, deny),
		"deny before allow, separate documents": acrossDocs(deny, allow),
		"deny after allow, one document":        withinDoc(allow, deny),
		"deny before allow, one document":       withinDoc(deny, allow),
	}
	for name, docs := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, iampolicy.Deny,
				iampolicy.EvaluateWithKeys("ec2:TerminateInstances", "*", docs, nil))
		})
	}
}

// An Allow the evaluator cannot enforce is dropped, but dropping it must not
// suppress a plain Allow that matches in another source.
func TestEvaluate_UnenforceableAllowDoesNotPoisonAnotherSource(t *testing.T) {
	docs := sourceSlice(map[string]iampolicy.Statement{
		"user-managed": {
			Effect:    "Allow",
			NotAction: iampolicy.StringOrArr{"ec2:TerminateInstances"},
			Resource:  iampolicy.StringOrArr{"*"},
		},
		"group-inline": stmt("Allow", "ec2:RunInstances", "*"),
	})

	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", docs, nil))
	// The NotAction Allow granted nothing, so the action it would have covered
	// falls back to the implicit deny.
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("ec2:DescribeInstances", "*", docs, nil))
}

// A Deny the evaluator cannot enforce fails closed, so it must override an Allow
// held in another source rather than disappearing.
func TestEvaluate_UnenforceableDenyOverridesAnotherSource(t *testing.T) {
	docs := sourceSlice(map[string]iampolicy.Statement{
		"user-managed": stmt("Allow", "ec2:*", "*"),
		"role-inline": {
			Effect:      "Deny",
			Action:      iampolicy.StringOrArr{"ec2:TerminateInstances"},
			NotResource: iampolicy.StringOrArr{"arn:aws:ec2:ap-southeast-2:111122223333:instance/i-keep"},
		},
	})

	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("ec2:TerminateInstances", "*", docs, nil))
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", docs, nil))
}

// A Deny carrying a variable this door cannot resolve selects everything it
// might have, across the source boundary.
func TestEvaluate_UnresolvableDenyOverridesAnotherSource(t *testing.T) {
	docs := sourceSlice(map[string]iampolicy.Statement{
		"user-managed": stmt("Allow", "s3:*", "arn:aws:s3:::shared/*"),
		"group-inline": stmt("Deny", "s3:*", "arn:aws:s3:::shared/${aws:username}/*"),
	})

	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::shared/alice/report", docs, nil))

	// Resolved, the Deny narrows to the caller's own prefix and the Allow stands
	// everywhere else.
	keys := iampolicy.ConditionKeys{iampolicy.KeyUsername: "alice"}
	assert.Equal(t, iampolicy.Deny,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::shared/alice/report", docs, keys))
	assert.Equal(t, iampolicy.Allow,
		iampolicy.EvaluateWithKeys("s3:GetObject", "arn:aws:s3:::shared/bob/report", docs, keys))
}

// Degenerate documents are inert in both directions: they neither grant nor
// take away, so a grant in another source survives one.
func TestEvaluate_DegenerateDocumentShapes(t *testing.T) {
	cases := []struct {
		name     string
		policies []iampolicy.PolicyDocument
		want     iampolicy.Decision
	}{
		{"nil slice", nil, iampolicy.Deny},
		{"empty slice", []iampolicy.PolicyDocument{}, iampolicy.Deny},
		{"every source empty", sourceSlice(nil), iampolicy.Deny},
		{
			name: "allow with no Action grants nothing",
			policies: sourceSlice(map[string]iampolicy.Statement{
				"user-inline": {Effect: "Allow", Resource: iampolicy.StringOrArr{"*"}},
			}),
			want: iampolicy.Deny,
		},
		{
			name: "allow with no Resource grants nothing",
			policies: sourceSlice(map[string]iampolicy.Statement{
				"user-inline": {Effect: "Allow", Action: iampolicy.StringOrArr{"ec2:*"}},
			}),
			want: iampolicy.Deny,
		},
		{
			name: "deny with no Action takes nothing away",
			policies: sourceSlice(map[string]iampolicy.Statement{
				"user-managed": stmt("Allow", "ec2:*", "*"),
				"role-inline":  {Effect: "Deny", Resource: iampolicy.StringOrArr{"*"}},
			}),
			want: iampolicy.Allow,
		},
		{
			name: "deny with no Resource takes nothing away",
			policies: sourceSlice(map[string]iampolicy.Statement{
				"user-managed": stmt("Allow", "ec2:*", "*"),
				"role-inline":  {Effect: "Deny", Action: iampolicy.StringOrArr{"ec2:*"}},
			}),
			want: iampolicy.Allow,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want,
				iampolicy.EvaluateWithKeys("ec2:RunInstances", "*", tc.policies, nil))
		})
	}
}
