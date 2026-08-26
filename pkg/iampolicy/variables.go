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

// expansion reports what expandVariables could make of a string.
type expansion int

const (
	// expansionResolved: every reference resolved; use the returned string.
	expansionResolved expansion = iota
	// expansionLiteral: nothing here the evaluator owns, so the input means
	// what it meant before variables existed. Compare it as written.
	expansionLiteral
	// expansionUnresolvable: a substitutable key this door cannot supply, so
	// the pattern selects nothing rather than collapsing.
	expansionUnresolvable
)

// Bytes expandVariables backslash-escapes when the caller will glob-match the
// result: the metacharacters a substituted value must not introduce, and the
// escape character itself wherever it appears.
const (
	escapesInText  = `\`
	escapesInValue = `\*?`
)

// expandVariables resolves ${key} in s against the request context. A
// present-but-empty key substitutes empty. A reference the evaluator does not
// own is left alone: "${" is legal in an ARN and predates this syntax.
//
// Substituted text is never rescanned, so resolution is single pass. escapeMeta
// escapes metacharacters in substituted values, so a value cannot act as a
// wildcard when matchGlob reads the result back.
func expandVariables(s string, keys ConditionKeys, escapeMeta bool) (string, expansion) {
	if !strings.Contains(s, variablePrefix) {
		return s, expansionLiteral
	}

	textChars, valueChars := "", ""
	if escapeMeta {
		textChars, valueChars = escapesInText, escapesInValue
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		open := strings.Index(s[i:], variablePrefix)
		if open < 0 {
			writeEscaped(&b, s[i:], textChars)
			break
		}
		writeEscaped(&b, s[i:i+open], textChars)
		i += open + len(variablePrefix)

		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return s, expansionLiteral
		}
		name := s[i : i+end]
		i += end + 1

		value, ok := literalVariables[name]
		if !ok {
			if !substitutableKeys[name] {
				return s, expansionLiteral
			}
			if value, ok = keys[name]; !ok {
				return "", expansionUnresolvable
			}
		}
		writeEscaped(&b, value, valueChars)
	}
	return b.String(), expansionResolved
}

// writeEscaped copies s, prefixing every byte in chars with a backslash. An
// empty chars copies s verbatim, for callers comparing it literally.
func writeEscaped(b *strings.Builder, s, chars string) {
	if !strings.ContainsAny(s, chars) {
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
