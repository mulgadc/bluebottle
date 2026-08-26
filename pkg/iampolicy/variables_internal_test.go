package iampolicy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// aliceKeys is the condition context of a request from user alice.
var aliceKeys = ConditionKeys{
	KeyUsername:         "alice",
	KeyPrincipalAccount: "000000000001",
	KeyUserID:           "AIDAALICE",
}

// Resolution without escaping, the form the exact-comparison operators use.
func TestExpandVariables(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		keys  ConditionKeys
		want  string
		wantK bool
	}{
		{"no reference", "arn:aws:s3:::home/*", aliceKeys, "arn:aws:s3:::home/*", true},
		{"username", "arn:aws:s3:::home/${aws:username}/*", aliceKeys, "arn:aws:s3:::home/alice/*", true},
		{"account", "${aws:PrincipalAccount}", aliceKeys, "000000000001", true},
		{"userid", "${aws:userid}", aliceKeys, "AIDAALICE", true},
		{"two references", "${aws:username}-${aws:userid}", aliceKeys, "alice-AIDAALICE", true},

		// A door that cannot supply the key makes the pattern unresolvable.
		{"absent key", "home/${aws:username}/*", ConditionKeys{}, "", false},
		{"nil keys", "home/${aws:username}/*", nil, "", false},
		{"not substitutable", "home/${aws:SourceIp}/*", aliceKeys, "", false},
		{"unknown key", "home/${nonsense}/*", aliceKeys, "", false},
		{"unterminated", "home/${aws:username", aliceKeys, "", false},

		// Present but empty is a real value, kept distinct from absent.
		{"empty value", "home/${aws:username}/*", ConditionKeys{KeyUsername: ""}, "home//*", true},

		// AWS's literal escapes.
		{"literal star", "home/${*}/*", aliceKeys, "home/*/*", true},
		{"literal question", "home/${?}", aliceKeys, "home/?", true},
		{"literal dollar", "${$}{aws:username}", aliceKeys, "${aws:username}", true},

		// Single pass: a substituted value carrying "${" is not re-expanded.
		{"value holds a reference", "${aws:username}", ConditionKeys{KeyUsername: "${aws:userid}"}, "${aws:userid}", true},
	}

	for _, tt := range tests {
		got, ok := expandVariables(tt.in, tt.keys, false)
		assert.Equal(t, tt.wantK, ok, "expandVariables(%q) resolved", tt.in)
		assert.Equal(t, tt.want, got, "expandVariables(%q)", tt.in)
	}
}

// escapeMeta escapes metacharacters in a substituted value, so a principal
// attribute cannot widen the pattern it lands in.
func TestExpandVariables_EscapesSubstitutedMetacharacters(t *testing.T) {
	got, ok := expandVariables("home/${aws:username}/*", ConditionKeys{KeyUsername: "*"}, true)
	assert.True(t, ok)
	assert.Equal(t, `home/\*/*`, got)

	got, ok = expandVariables("home/${aws:username}/*", ConditionKeys{KeyUsername: "a?b"}, true)
	assert.True(t, ok)
	assert.Equal(t, `home/a\?b/*`, got)

	// A backslash is escaped on both sides, so the escape character is never
	// mistaken for one the expander introduced.
	got, ok = expandVariables(`a\b/${aws:username}`, ConditionKeys{KeyUsername: `c\d`}, true)
	assert.True(t, ok)
	assert.Equal(t, `a\\b/c\\d`, got)

	// The pattern's own metacharacters keep their meaning.
	got, ok = expandVariables("home/${aws:username}/?*", aliceKeys, true)
	assert.True(t, ok)
	assert.Equal(t, "home/alice/?*", got)

	// ${*} is the literal form, so it is escaped like a substituted value.
	got, ok = expandVariables("home/${*}", aliceKeys, true)
	assert.True(t, ok)
	assert.Equal(t, `home/\*`, got)
}

// The write-path gate: anything unresolvable is reportable before storage.
func TestUnsupportedVariable(t *testing.T) {
	tests := []struct {
		in    string
		key   string
		found bool
	}{
		{"arn:aws:s3:::home/*", "", false},
		{"arn:aws:s3:::home/${aws:username}/*", "", false},
		{"${aws:PrincipalAccount}/${aws:userid}", "", false},
		{"${*}${?}${$}", "", false},
		{"home/${aws:SourceIp}/*", "aws:SourceIp", true},
		{"home/${nonsense}/*", "nonsense", true},
		{"home/${aws:username}/${bogus}", "bogus", true},
		{"home/${aws:username", "aws:username", true},
		{"${}", "", true},

		// A "$" that does not open a reference is ordinary text.
		{"home/$aws:username/*", "", false},
	}

	for _, tt := range tests {
		key, found := UnsupportedVariable(tt.in)
		assert.Equal(t, tt.found, found, "UnsupportedVariable(%q) found", tt.in)
		assert.Equal(t, tt.key, key, "UnsupportedVariable(%q) key", tt.in)
	}
}

// A literal escape must not collide with a real key name.
func TestSubstitutableKeys_AreDisjointFromLiterals(t *testing.T) {
	for name := range literalVariables {
		assert.False(t, substitutableKeys[name], "%q is both a literal escape and a key", name)
	}
}
