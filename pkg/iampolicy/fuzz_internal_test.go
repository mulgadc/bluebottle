package iampolicy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Any document that decodes re-encodes, and the re-encoding decodes back to the
// same value. The first decode normalises scalars to strings, so the fixed
// point is decode→encode→decode rather than byte equality with the input.
func FuzzConditionValueDecode(f *testing.F) {
	for _, seed := range []string{
		`"a"`, `["a","b"]`, `[]`, `null`, `true`, `10`, `1e3`, `-0.5`,
		`[true,1,"x"]`, `[null]`, `{}`, `[[]]`, `"\ud800"`, `"a" "b"`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var first ConditionValue
		if json.Unmarshal(data, &first) != nil {
			return
		}
		enc, err := json.Marshal(first)
		require.NoError(t, err)
		var second ConditionValue
		require.NoError(t, json.Unmarshal(enc, &second), "re-encoding %s", enc)
		assert.Equal(t, first, second)
	})
}

func FuzzStringOrArrDecode(f *testing.F) {
	for _, seed := range []string{
		`"s3:GetObject"`, `["s3:Get*","s3:List*"]`, `[]`, `null`, `[null]`,
		`1`, `true`, `{}`, `[1]`, `"\ud800"`, `["a",null]`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var first StringOrArr
		if json.Unmarshal(data, &first) != nil {
			return
		}
		enc, err := json.Marshal(first)
		require.NoError(t, err)
		var second StringOrArr
		require.NoError(t, json.Unmarshal(enc, &second), "re-encoding %s", enc)
		assert.Equal(t, first, second)
	})
}

// globElem is one pattern element for the reference matcher.
type globElem struct {
	b          byte
	star, any1 bool
}

// referenceGlob is an O(len(pattern)*len(value)) DP over the same grammar as
// matchGlob, written independently of its greedy backtracking scan.
func referenceGlob(pattern, value string, escapes bool) bool {
	var elems []globElem
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case escapes && c == '\\' && i+1 < len(pattern):
			i++
			elems = append(elems, globElem{b: pattern[i]})
		case c == '*':
			elems = append(elems, globElem{star: true})
		case c == '?':
			elems = append(elems, globElem{any1: true})
		default:
			elems = append(elems, globElem{b: c})
		}
	}
	// dp[j] reports whether elems[:i] matches value[:j], rolled over i.
	dp := make([]bool, len(value)+1)
	dp[0] = true
	for _, e := range elems {
		next := make([]bool, len(value)+1)
		for j := 0; j <= len(value); j++ {
			switch {
			case e.star:
				next[j] = dp[j] || (j > 0 && next[j-1])
			case j == 0:
			case e.any1 || e.b == value[j-1]:
				next[j] = dp[j-1]
			}
		}
		dp = next
	}
	return dp[len(value)]
}

func FuzzMatchGlob(f *testing.F) {
	f.Add("a*a*a*b", "aaaaaaaaaaaaaaaaaaaa", false)
	f.Add(`arn:aws:iam::*:role/app-*`, "arn:aws:iam::1:role/app-x", false)
	f.Add(`home/\*/?`, "home/*/x", true)
	f.Add(`a\`, `a\`, true)
	f.Add(`\\*`, `\abc`, true)
	f.Add("", "", false)
	f.Add("**?", "", true)
	f.Fuzz(func(t *testing.T, pattern, value string, escapes bool) {
		if len(pattern) > 256 || len(value) > 256 {
			return
		}
		want := referenceGlob(pattern, value, escapes)
		assert.Equal(t, want, matchGlob(pattern, value, escapes),
			"pattern %q value %q escapes %v", pattern, value, escapes)
		if !escapes {
			assert.Equal(t, want, MatchWildcard(pattern, value),
				"MatchWildcard pattern %q value %q", pattern, value)
		}
	})
}

// Cross-checks expandVariables against UnresolvableVariable, which scans with
// its own loop, and checks the escaped form against matchGlob. Every
// substitutable key is present, so resolution fails only on a bad reference.
func FuzzExpandVariables(f *testing.F) {
	f.Add("home/${aws:username}/*", "alice", "000000000001", "AIDA", "home/alice/x")
	f.Add("${aws:username}", "a*b?c\\", "", "", "axbyc\\")
	f.Add("${*}${?}${$}", "", "", "", "*?$")
	f.Add("${aws:SourceIp}", "", "", "", "")
	f.Add("a${aws:userid", "", "", "", "")
	f.Add(`\${aws:PrincipalAccount}\`, "*", "1", "", `\1\`)
	f.Add("${}${${aws:username}}", "x", "", "", "")
	f.Fuzz(func(t *testing.T, s, user, account, userID, probe string) {
		if len(s) > 256 || len(probe) > 256 {
			return
		}
		keys := ConditionKeys{KeyUsername: user, KeyPrincipalAccount: account, KeyUserID: userID}

		plain, plainResult := expandVariables(s, keys, false)
		escaped, escapedResult := expandVariables(s, keys, true)
		require.Equal(t, plainResult, escapedResult, "escaping changed the verdict for %q", s)

		_, fault := UnresolvableVariable(s)
		switch {
		case !strings.Contains(s, VariablePrefix):
			require.Equal(t, expansionLiteral, plainResult)
			assert.Equal(t, s, plain)
			assert.Equal(t, s, escaped)
			return
		case fault != VariableOK:
			require.Equal(t, expansionUnresolvable, plainResult, "%q has fault %v", s, fault)
			return
		default:
			require.Equal(t, expansionResolved, plainResult, "%q has no fault", s)
		}

		// The escaped pattern always matches the plain expansion: escaped
		// values and "\" match only themselves, and text wildcards match
		// their own literal character.
		assert.True(t, matchGlob(escaped, plain, true),
			"escaped %q does not match plain %q", escaped, plain)

		// With no wildcard written in the pattern itself, it matches exactly its
		// expansion: no substituted "*" or "?" may act as a wildcard.
		if !strings.ContainsAny(s, "*?") {
			assert.Equal(t, probe == plain, matchGlob(escaped, probe, true),
				"escaped %q probe %q plain %q", escaped, probe, plain)
		}
	})
}
