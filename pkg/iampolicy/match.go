package iampolicy

import "strings"

// MatchWildcard reports whether value matches pattern, where "*" matches zero or
// more characters at any position (infix) and "?" matches exactly one character,
// as the AWS IAM Action and Resource grammar requires (e.g.
// arn:aws:iam::*:role/app-*). Matching is case-sensitive; callers that need
// case-insensitivity lower-case both inputs first.
//
// Metacharacters are matched over bytes, not runes: IAM ARNs and action names
// are ASCII, and IAM has no escape syntax, so a literal "?" cannot be expressed
// in a pattern.
func MatchWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}

	// Greedy scan with a single backtrack point at the most recent "*", which
	// keeps patterns like a*a*a*b linear rather than exponential.
	var p, v int
	star, starV := -1, 0
	for v < len(value) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]):
			p++
			v++
		case p < len(pattern) && pattern[p] == '*':
			star, starV = p, v
			p++
		case star >= 0:
			starV++
			p, v = star+1, starV
		default:
			return false
		}
	}

	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
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
