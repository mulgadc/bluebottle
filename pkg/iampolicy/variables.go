package iampolicy

import "strings"

// variablePrefix opens a policy variable, as in home/${aws:username}/*.
const variablePrefix = "${"

// substitutableKeys are the ${key} references the evaluator can resolve:
// deliberately not supportedConditions, but the keys identifying the caller.
var substitutableKeys = map[string]bool{
	KeyUsername:         true,
	KeyPrincipalAccount: true,
	KeyUserID:           true,
}

// literalVariables are AWS's escape forms: ${*}, ${?} and ${$} stand for the
// literal character, the only way to write one in a pattern.
var literalVariables = map[string]string{"*": "*", "?": "?", "$": "$"}

// UnsupportedVariable returns the first ${...} reference in s the evaluator
// cannot resolve, for write paths to reject rather than store a policy that is
// inert at every door. An unterminated "${" reports the remaining text.
func UnsupportedVariable(s string) (key string, found bool) {
	for i := 0; i < len(s); {
		open := strings.Index(s[i:], variablePrefix)
		if open < 0 {
			return "", false
		}
		i += open + len(variablePrefix)
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return s[i:], true
		}
		name := s[i : i+end]
		if _, literal := literalVariables[name]; !literal && !substitutableKeys[name] {
			return name, true
		}
		i += end + 1
	}
	return "", false
}

// expandVariables resolves ${key} in s against the request context, reporting
// false for a key that is not substitutable, absent, or unterminated. A
// present-but-empty key substitutes empty.
//
// Substituted text is never rescanned, so resolution is single pass. escapeMeta
// escapes "*" and "?" in values and "\" throughout, so a value cannot act as a
// wildcard when matchGlob reads the result back.
func expandVariables(s string, keys ConditionKeys, escapeMeta bool) (string, bool) {
	if !strings.Contains(s, variablePrefix) {
		return s, true
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		open := strings.Index(s[i:], variablePrefix)
		if open < 0 {
			writeEscaped(&b, s[i:], escapeMeta, `\`)
			break
		}
		writeEscaped(&b, s[i:i+open], escapeMeta, `\`)
		i += open + len(variablePrefix)

		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", false
		}
		name := s[i : i+end]
		i += end + 1

		value, ok := literalVariables[name]
		if !ok {
			if !substitutableKeys[name] {
				return "", false
			}
			if value, ok = keys[name]; !ok {
				return "", false
			}
		}
		writeEscaped(&b, value, escapeMeta, `\*?`)
	}
	return b.String(), true
}

// writeEscaped copies s, prefixing every byte in chars with a backslash. With
// escape false it copies s verbatim, for callers comparing it literally.
func writeEscaped(b *strings.Builder, s string, escape bool, chars string) {
	if !escape {
		b.WriteString(s)
		return
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(chars, s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
}
