package iampolicy

import (
	"maps"
	"slices"
	"strings"
)

// VariablePrefix opens a policy variable, as in home/${aws:username}/*.
const VariablePrefix = "${"

// substitutableKeys are the ${key} references the evaluator can resolve:
// deliberately not supportedConditions, but the keys identifying the caller.
// Every door supplies every key here for at least one principal type; one that
// no door supplies would make a pattern naming it fail closed everywhere.
var substitutableKeys = map[string]bool{
	KeyUsername:         true,
	KeyPrincipalAccount: true,
	KeyUserID:           true,
}

// SubstitutableKeys returns the keys a ${...} reference may name, sorted, for a
// write path to name in the error it rejects an unsupported reference with. It
// reads the registry the evaluator expands against, so the two cannot drift.
//
// The slice is freshly built on every call and owned by the caller.
func SubstitutableKeys() []string {
	return slices.Sorted(maps.Keys(substitutableKeys))
}

// literalVariables are AWS's escape forms: ${*}, ${?} and ${$} stand for the
// literal character, the only way to write one in a pattern.
var literalVariables = map[string]string{"*": "*", "?": "?", "$": "$"}

// VariableFault says why a ${...} reference cannot be resolved. The two faults
// need different wording from a write path, and only the scan knows which
// applies: a caller cannot tell them apart from the reported text, because an
// unknown key and an unterminated one can spell the same thing.
type VariableFault int

const (
	// VariableOK: every reference in the string is one the evaluator resolves.
	VariableOK VariableFault = iota
	// VariableUnknownKey: the reference is closed but names a key no door
	// supplies, so it resolves nowhere.
	VariableUnknownKey
	// VariableUnterminated: the reference has no closing brace.
	VariableUnterminated
)

// UnresolvableVariable returns the first ${...} reference in s the evaluator
// cannot resolve, and why, for write paths to reject rather than store a policy
// that is inert at every door. An unterminated "${" reports the remaining text.
func UnresolvableVariable(s string) (key string, fault VariableFault) {
	for i := 0; i < len(s); {
		open := strings.Index(s[i:], VariablePrefix)
		if open < 0 {
			return "", VariableOK
		}
		i += open + len(VariablePrefix)
		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return s[i:], VariableUnterminated
		}
		name := s[i : i+end]
		if _, literal := literalVariables[name]; !literal && !substitutableKeys[name] {
			return name, VariableUnknownKey
		}
		i += end + 1
	}
	return "", VariableOK
}

// UnsupportedVariable reports whether s carries a reference the evaluator cannot
// resolve, discarding which of the two faults it is. Callers that put the fault
// in front of an operator want UnresolvableVariable instead.
func UnsupportedVariable(s string) (key string, found bool) {
	key, fault := UnresolvableVariable(s)
	return key, fault != VariableOK
}

// expansion reports what expandVariables could make of a string.
type expansion int

const (
	// expansionResolved: every reference resolved; use the returned string.
	expansionResolved expansion = iota
	// expansionLiteral: the input has no variable references. Compare it as
	// written, using the ordinary IAM pattern grammar.
	expansionLiteral
	// expansionUnresolvable: a reference is unsupported, malformed, or absent
	// from this door's context, so the pattern selects nothing.
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
// present-but-empty key substitutes empty. An unsupported, absent, or
// unterminated reference is unresolvable and makes its pattern select nothing.
//
// Substituted text is never rescanned, so resolution is single pass. escapeMeta
// escapes metacharacters in substituted values, so a value cannot act as a
// wildcard when matchGlob reads the result back.
func expandVariables(s string, keys ConditionKeys, escapeMeta bool) (string, expansion) {
	if !strings.Contains(s, VariablePrefix) {
		return s, expansionLiteral
	}

	textChars, valueChars := "", ""
	if escapeMeta {
		textChars, valueChars = escapesInText, escapesInValue
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		open := strings.Index(s[i:], VariablePrefix)
		if open < 0 {
			writeEscaped(&b, s[i:], textChars)
			break
		}
		writeEscaped(&b, s[i:i+open], textChars)
		i += open + len(VariablePrefix)

		end := strings.IndexByte(s[i:], '}')
		if end < 0 {
			return "", expansionUnresolvable
		}
		name := s[i : i+end]
		i += end + 1

		value, ok := literalVariables[name]
		if !ok {
			if !substitutableKeys[name] {
				return "", expansionUnresolvable
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
