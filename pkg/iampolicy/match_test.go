package iampolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMatchWildcard exercises the case-sensitive infix matcher directly. Case
// folding is the caller's job (via matchesAny), so mixed-case here must NOT match.
func TestMatchWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// Global wildcard.
		{"*", "anything", true},
		{"*", "", true},

		// Service wildcard (case-sensitive at this level).
		{"ec2:*", "ec2:RunInstances", true},
		{"ec2:*", "ec2:DescribeInstances", true},
		{"ec2:*", "s3:GetObject", false},
		{"EC2:*", "ec2:RunInstances", false},

		// Prefix wildcard.
		{"s3:Get*", "s3:GetObject", true},
		{"s3:Get*", "s3:GetBucketPolicy", true},
		{"s3:Get*", "s3:PutObject", false},

		// Exact match (case-sensitive).
		{"ec2:RunInstances", "ec2:RunInstances", true},
		{"ec2:RunInstances", "ec2:StopInstances", false},
		{"ec2:RunInstances", "EC2:RunInstances", false},

		// Infix wildcards (AWS IAM-style — required for iam:PassRole ARN matching).
		{"arn:aws:iam::*:role/app-*", "arn:aws:iam::123456789012:role/app-foo", true},
		{"arn:aws:iam::*:role/app-*", "arn:aws:iam::999999999999:role/app-bar", true},
		{"arn:aws:iam::*:role/*", "arn:aws:iam::123456789012:role/anything", true},
		{"arn:aws:iam::123456789012:role/app-*", "arn:aws:iam::123456789012:role/app-foo", true},
		{"arn:aws:iam::*:role/app-*", "arn:aws:iam::123456789012:role/admin-foo", false},
		{"arn:aws:iam::*:role/app-*", "arn:aws:iam::123456789012:user/app-foo", false},
		{"arn:aws:iam::*:role/app-*", "arn:aws:iam::123456789012:role/app-", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},

		// S3 suffix ARNs, case-sensitive.
		{"arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/key.txt", true},
		{"arn:aws:s3:::my-bucket/*", "arn:aws:s3:::other-bucket/key.txt", false},
		{"arn:aws:s3:::MyBucket", "arn:aws:s3:::MyBucket", true},
		{"arn:aws:s3:::MyBucket", "arn:aws:s3:::mybucket", false},

		// Single-character wildcard.
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "abbc", false},

		// "?" never matches the empty string.
		{"abc?", "abc", false},
		{"?", "", false},
		{"?", "a", true},

		// "?" at pattern start and end.
		{"?bc", "abc", true},
		{"?bc", "bc", false},
		{"ab?", "abc", true},

		// "?" combined with "*".
		{"a?*c", "abxc", true},
		{"a?*c", "ac", false},
		{"arn:aws:s3:::secret?/*", "arn:aws:s3:::secrets/object", true},
		{"arn:aws:s3:::secret?/*", "arn:aws:s3:::secret/object", false},

		// A literal "?" in the value: the metacharacter matches it, a literal
		// pattern byte does not.
		{"a?c", "a?c", true},
		{"abc", "a?c", false},

		// An unescaped "*" in the pattern stays a wildcard even when the value
		// contains a literal "*" at the same offset.
		{"a*", "a*c", true},
		{"a*c", "a*c", true},

		// Backtracking.
		{"a*b?c", "axxbyc", true},
		{"*?", "a", true},
		{"a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},

		// Edge cases.
		{"", "", true},
		{"", "something", false},

		// IAM has no escape syntax, so a backslash is an ordinary literal and
		// the "*" after it is still a wildcard.
		{`a\*c`, `a\bc`, true},
		{`a\*c`, "a*c", false},
		{`a\bc`, `a\bc`, true},
	}

	for _, tt := range tests {
		got := MatchWildcard(tt.pattern, tt.value)
		assert.Equal(t, tt.want, got, "MatchWildcard(%q, %q)", tt.pattern, tt.value)
	}
}

// The escaped form, which only expandVariables produces: it stops a "*" in a
// substituted value acting as a wildcard.
func TestMatchGlob_Escapes(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// An escaped metacharacter matches only itself.
		{`a\*c`, "a*c", true},
		{`a\*c`, "abc", false},
		{`a\*c`, "axxxc", false},
		{`a\?c`, "a?c", true},
		{`a\?c`, "abc", false},

		// The escape character itself.
		{`a\\c`, `a\c`, true},
		{`a\\c`, "abc", false},
		{`a\`, `a\`, true},

		// Unescaped metacharacters keep their meaning alongside escaped ones.
		{`home/\*/*`, "home/*/anything", true},
		{`home/\*/*`, "home/alice/anything", false},
		{`home/alice/*`, "home/alice/anything", true},

		// Backtracking still resumes correctly past an escaped element.
		{`a*b\?c`, "axxb?c", true},
		{`a*b\?c`, "axxbyc", false},
		{`a*a*a*b`, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, matchGlob(tt.pattern, tt.value, true),
			"matchGlob(%q, %q, true)", tt.pattern, tt.value)
	}
}

// The resource path with failClosed off, the Allow arm: variables resolve, and
// an unresolvable one matches nothing.
func TestMatchesAnyResource(t *testing.T) {
	patterns := []string{"arn:aws:s3:::home/${aws:username}/*"}

	assert.True(t, matchesAnyResource(patterns, "arn:aws:s3:::home/alice/object", aliceKeys, false))
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/bob/object", aliceKeys, false))
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/alice/object", nil, false))

	// A username holding a metacharacter is matched literally.
	star := ConditionKeys{KeyUsername: "*"}
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/bob/object", star, false))
	assert.True(t, matchesAnyResource(patterns, "arn:aws:s3:::home/*/object", star, false))

	// Patterns without a reference behave exactly as before, including a
	// backslash, which the IAM grammar treats as an ordinary literal.
	assert.True(t, matchesAnyResource([]string{"arn:aws:s3:::*"}, "arn:aws:s3:::any", nil, false))
	assert.False(t, matchesAnyResource([]string{"arn:aws:s3:::b"}, "arn:aws:s3:::B", nil, false))
	assert.True(t, matchesAnyResource([]string{`arn:aws:s3:::b/a\b*`}, `arn:aws:s3:::b/a\bx`, nil, false))
	assert.False(t, matchesAnyResource([]string{`arn:aws:s3:::b/a\b*`}, "arn:aws:s3:::b/abx", nil, false))

	// Unsupported and malformed references match nothing, including resources
	// containing the placeholder text literally.
	env := []string{"arn:aws:s3:::b/${env}/*"}
	assert.False(t, matchesAnyResource(env, "arn:aws:s3:::b/${env}/config", aliceKeys, false))
	assert.False(t, matchesAnyResource(env, "arn:aws:s3:::b/prod/config", aliceKeys, false))
	assert.False(t, matchesAnyResource([]string{"arn:aws:s3:::b/${env"}, "arn:aws:s3:::b/${env", nil, false))

	// One unresolvable pattern does not veto the rest of the list.
	mixed := []string{"arn:aws:s3:::home/${aws:username}/*", "arn:aws:s3:::public/*"}
	assert.True(t, matchesAnyResource(mixed, "arn:aws:s3:::public/x", nil, false))

	// Case-sensitive, like the resource half of matchesAny.
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/ALICE/object", aliceKeys, false))
}

// The Deny arm: an unresolvable reference matches, so the restriction survives a
// door that cannot supply the key rather than silently disappearing.
func TestMatchesAnyResource_FailClosedMatchesUnresolvable(t *testing.T) {
	patterns := []string{"arn:aws:s3:::home/${aws:username}/*"}

	assert.True(t, matchesAnyResource(patterns, "arn:aws:s3:::home/bob/object", nil, true))
	assert.True(t, matchesAnyResource([]string{"arn:aws:s3:::b/${env}/*"}, "arn:aws:s3:::b/prod/x", nil, true))
	assert.True(t, matchesAnyResource([]string{"arn:aws:s3:::b/${env"}, "arn:aws:s3:::anything", nil, true))

	// A resolvable reference is unaffected: it still matches on its own terms,
	// so failing closed never widens a Deny past the resources it names.
	assert.True(t, matchesAnyResource(patterns, "arn:aws:s3:::home/alice/object", aliceKeys, true))
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/bob/object", aliceKeys, true))

	// A pattern with no reference at all is untouched by failClosed.
	assert.False(t, matchesAnyResource([]string{"arn:aws:s3:::other/*"}, "arn:aws:s3:::b/x", nil, true))
}

// The whole pattern grammar end to end through matchesAnyResource, in both
// arms. Each case names whether the pattern is unresolvable, and the closed arm
// is derived from that rather than written out: an unresolvable pattern matches
// under failClosed, everything else behaves identically in both arms.
func TestMatchesAnyResource_PatternGrammar(t *testing.T) {
	const b = "arn:aws:s3:::b/"
	star := ConditionKeys{KeyUsername: "a*c"}
	question := ConditionKeys{KeyUsername: "a?c"}
	backslash := ConditionKeys{KeyUsername: `a\c`}
	empty := ConditionKeys{KeyUsername: ""}

	tests := []struct {
		pattern      string
		value        string
		keys         ConditionKeys
		want         bool
		unresolvable bool
	}{
		// The metacharacters, with no reference in play.
		{b + "*", b + "anything", aliceKeys, true, false},
		{b + "a?c", b + "abc", aliceKeys, true, false},
		{b + "a?c", b + "ac", aliceKeys, false, false},

		// AWS's literal escapes: the only way to write a metacharacter.
		{b + "${*}", b + "*", aliceKeys, true, false},
		{b + "${*}", b + "x", aliceKeys, false, false},
		{b + "${?}", b + "?", aliceKeys, true, false},
		{b + "${?}", b + "x", aliceKeys, false, false},
		{b + "${$}", b + "$", aliceKeys, true, false},
		{b + "${$}{aws:username}", b + "${aws:username}", aliceKeys, true, false},

		// A reference adjacent to a metacharacter keeps both meanings.
		{b + "${aws:username}*", b + "alice-2024", aliceKeys, true, false},
		{b + "${aws:username}*", b + "bob-2024", aliceKeys, false, false},
		{b + "*${aws:username}", b + "2024-alice", aliceKeys, true, false},
		{b + "?${aws:username}", b + "-alice", aliceKeys, true, false},
		{b + "${aws:username}${aws:userid}", b + "aliceAIDAALICE", aliceKeys, true, false},

		// A substituted value never acts as a wildcard, however it is spelled.
		{b + "${aws:username}", b + "a*c", star, true, false},
		{b + "${aws:username}", b + "abc", star, false, false},
		{b + "${aws:username}/*", b + "abc/x", star, false, false},
		{b + "${aws:username}", b + "a?c", question, true, false},
		{b + "${aws:username}", b + "abc", question, false, false},
		{b + "${aws:username}", `arn:aws:s3:::b/a\c`, backslash, true, false},
		{b + "${aws:username}", b + "ac", backslash, false, false},

		// Present but empty substitutes empty; it is not absent.
		{b + "${aws:username}/x", b + "/x", empty, true, false},

		// Malformed and unsupported references resolve to nothing, so they match
		// under failClosed and nothing under it.
		{b + "${", b + "${", aliceKeys, false, true},
		{b + "${}", b + "${}", aliceKeys, false, true},
		{b + "${aws:username", b + "alice", aliceKeys, false, true},
		{b + "${aws:${aws:username}}", b + "alice", aliceKeys, false, true},
		{b + "${nonsense}", b + "anything", aliceKeys, false, true},
		{b + "${aws:SourceIp}", b + "10.1.2.3", aliceKeys, false, true},
		{b + "${aws:username}", b + "alice", nil, false, true},

		// A "$" that opens nothing is ordinary text.
		{b + "$aws:username", b + "$aws:username", aliceKeys, true, false},
		{b + "$aws:username", b + "alice", aliceKeys, false, false},
	}

	for _, tt := range tests {
		patterns := []string{tt.pattern}
		assert.Equal(t, tt.want, matchesAnyResource(patterns, tt.value, tt.keys, false),
			"open arm: matchesAnyResource(%q, %q)", tt.pattern, tt.value)
		assert.Equal(t, tt.want || tt.unresolvable, matchesAnyResource(patterns, tt.value, tt.keys, true),
			"closed arm: matchesAnyResource(%q, %q)", tt.pattern, tt.value)
	}
}

// TestMatchesAny covers the case-fold flag: actions fold (true), resources are
// exact-case (false).
func TestMatchesAny(t *testing.T) {
	// Case-insensitive (actions).
	assert.True(t, matchesAny([]string{"EC2:*"}, "ec2:RunInstances", true))
	assert.True(t, matchesAny([]string{"ec2:runinstances"}, "ec2:RunInstances", true))
	assert.True(t, matchesAny([]string{"S3:get*"}, "s3:GetObject", true))
	assert.False(t, matchesAny([]string{"s3:*"}, "ec2:RunInstances", true))

	// Case-sensitive (resources).
	assert.True(t, matchesAny([]string{"arn:aws:s3:::MyBucket"}, "arn:aws:s3:::MyBucket", false))
	assert.False(t, matchesAny([]string{"arn:aws:s3:::MyBucket"}, "arn:aws:s3:::mybucket", false))

	// Any-of-many.
	assert.True(t, matchesAny([]string{"s3:Get*", "s3:Put*"}, "s3:PutObject", true))
	assert.False(t, matchesAny([]string{"s3:Get*", "s3:Put*"}, "s3:DeleteObject", true))

	// Empty pattern set never matches.
	assert.False(t, matchesAny(nil, "s3:GetObject", true))
}
