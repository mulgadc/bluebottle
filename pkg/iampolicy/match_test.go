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

// The resource path: variables resolve, and an unresolvable one matches nothing.
func TestMatchesAnyResource(t *testing.T) {
	patterns := []string{"arn:aws:s3:::home/${aws:username}/*"}

	assert.True(t, matchesAnyResource(patterns, "arn:aws:s3:::home/alice/object", aliceKeys))
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/bob/object", aliceKeys))
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/alice/object", nil))

	// A username holding a metacharacter is matched literally.
	star := ConditionKeys{KeyUsername: "*"}
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/bob/object", star))
	assert.True(t, matchesAnyResource(patterns, "arn:aws:s3:::home/*/object", star))

	// Patterns without a reference behave exactly as before, including a
	// backslash, which the IAM grammar treats as an ordinary literal.
	assert.True(t, matchesAnyResource([]string{"arn:aws:s3:::*"}, "arn:aws:s3:::any", nil))
	assert.False(t, matchesAnyResource([]string{"arn:aws:s3:::b"}, "arn:aws:s3:::B", nil))
	assert.True(t, matchesAnyResource([]string{`arn:aws:s3:::b/a\b*`}, `arn:aws:s3:::b/a\bx`, nil))
	assert.False(t, matchesAnyResource([]string{`arn:aws:s3:::b/a\b*`}, "arn:aws:s3:::b/abx", nil))

	// Unsupported and malformed references match nothing, including resources
	// containing the placeholder text literally.
	env := []string{"arn:aws:s3:::b/${env}/*"}
	assert.False(t, matchesAnyResource(env, "arn:aws:s3:::b/${env}/config", aliceKeys))
	assert.False(t, matchesAnyResource(env, "arn:aws:s3:::b/prod/config", aliceKeys))
	assert.False(t, matchesAnyResource([]string{"arn:aws:s3:::b/${env"}, "arn:aws:s3:::b/${env", nil))

	// One unresolvable pattern does not veto the rest of the list.
	mixed := []string{"arn:aws:s3:::home/${aws:username}/*", "arn:aws:s3:::public/*"}
	assert.True(t, matchesAnyResource(mixed, "arn:aws:s3:::public/x", nil))

	// Case-sensitive, like the resource half of matchesAny.
	assert.False(t, matchesAnyResource(patterns, "arn:aws:s3:::home/ALICE/object", aliceKeys))
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
