package iampolicy

import (
	"log/slog"
	"strings"
)

// MatchWildcard reports whether value matches pattern, where "*" matches zero or
// more characters at any position (infix) and "?" matches exactly one character,
// as the AWS IAM Action and Resource grammar requires (e.g.
// arn:aws:iam::*:role/app-*). Matching is case-sensitive; callers that need
// case-insensitivity lower-case both inputs first.
//
// Metacharacters are matched over bytes, not runes: IAM ARNs and action names
// are ASCII, and IAM has no escape syntax, so a "\" here is an ordinary literal.
func MatchWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}
	return matchGlob(pattern, value, false)
}

// matchGlob is the shared scan behind MatchWildcard. When escapes is true a
// "\x" element matches a literal x, which is how an expanded policy variable
// keeps a "*" in a principal attribute from acting as a wildcard.
func matchGlob(pattern, value string, escapes bool) bool {
	// Greedy scan with a single backtrack point at the most recent "*", which
	// keeps patterns like a*a*a*b linear rather than exponential.
	var p, v int
	star, starV := -1, 0
	for v < len(value) {
		b, meta, width := token(pattern, p, escapes)
		switch {
		case meta && b == '*':
			star, starV = p, v
			p += width
		case width > 0 && (meta || b == value[v]):
			p += width
			v++
		case star >= 0:
			starV++
			p, v = star+1, starV
		default:
			return false
		}
	}

	for {
		b, meta, width := token(pattern, p, escapes)
		if !meta || b != '*' {
			break
		}
		p += width
	}
	return p == len(pattern)
}

// token decodes the pattern element at p: its byte, whether it is a
// metacharacter, and its width. Width zero means the pattern is exhausted, and a
// trailing "\" is an ordinary literal.
func token(pattern string, p int, escapes bool) (b byte, meta bool, width int) {
	if p >= len(pattern) {
		return 0, false, 0
	}
	if escapes && pattern[p] == '\\' && p+1 < len(pattern) {
		return pattern[p+1], false, 2
	}
	c := pattern[p]
	return c, c == '*' || c == '?', 1
}

// matchesAny reports whether any pattern matches value. When caseInsensitive is
// true both sides are lower-cased before wildcard matching (used for IAM
// actions); when false, matching is exact-case (used for resource ARNs).
func matchesAny(patterns []string, value string, caseInsensitive bool) bool {
	if caseInsensitive {
		value = strings.ToLower(value)
	}
	for _, p := range patterns {
		if caseInsensitive {
			p = strings.ToLower(p)
		}
		if MatchWildcard(p, value) {
			return true
		}
	}
	return false
}

// matchPattern reports whether pattern matches value, resolving policy
// variables first. Only the resolved form is glob-matched with escapes: an
// unresolved pattern keeps the IAM grammar, where "\" is an ordinary literal.
func matchPattern(pattern, value string, keys ConditionKeys) bool {
	switch expanded, result := expandVariables(pattern, keys, true); result {
	case expansionLiteral:
		return MatchWildcard(pattern, value)
	case expansionUnresolvable:
		slog.Warn("iampolicy: pattern carries a variable this request cannot resolve, matching nothing",
			"pattern", pattern)
		return false
	default:
		return matchGlob(expanded, value, true)
	}
}

// matchesAnyResource reports whether any resource pattern matches, resolving
// policy variables first. Matching is case-sensitive, per AWS.
func matchesAnyResource(patterns []string, resource string, keys ConditionKeys) bool {
	for _, p := range patterns {
		if matchPattern(p, resource, keys) {
			return true
		}
	}
	return false
}
