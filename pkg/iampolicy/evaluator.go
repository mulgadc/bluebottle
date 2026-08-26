package iampolicy

import (
	"bytes"
	"log/slog"
)

// Decision represents the outcome of a policy evaluation.
type Decision int

const (
	// Deny is the default — no matching Allow, or an explicit Deny.
	Deny Decision = iota
	// Allow means an explicit Allow was found with no overriding Deny.
	Allow
)

// EvaluateWithKeys reports whether action on resource is permitted by the
// supplied policy documents, following AWS's evaluation order:
//
//  1. Explicit Deny in any statement → Deny (wins immediately).
//  2. Explicit Allow in any statement → Allow.
//  3. No matching statement → Deny (implicit default).
//
// Actions match case-insensitively (AWS lower-cases service:verb); resource
// ARNs match case-sensitively (AWS spec). An unrecognized Effect fails closed to
// Deny with a warning. Root bypass, if any, is handled by the caller.
//
// keys carries the request's condition context keys. A condition on a key the
// caller cannot supply evaluates false, per AWS, so the same policy legitimately
// gives different answers at different doors. Passing nil fails every condition.
//
// Resource patterns and string condition values may carry ${key} policy
// variables, resolved from keys. An unresolvable one makes the statement
// non-matching, for Allow and Deny alike.
func EvaluateWithKeys(action, resource string, policies []PolicyDocument, keys ConditionKeys) Decision {
	hasAllow := false
	for i := range policies {
		for j := range policies[i].Statement {
			stmt := &policies[i].Statement[j]

			if !stmt.matches(action, resource, keys) {
				continue
			}
			switch stmt.Effect {
			case EffectDeny:
				return Deny
			case EffectAllow:
				hasAllow = true
			default:
				slog.Warn("iampolicy: unrecognized Effect, treating as Deny",
					"effect", stmt.Effect, "action", action)
				return Deny
			}
		}
	}

	if hasAllow {
		return Allow
	}
	return Deny
}

// matches reports whether the statement selects action on resource under keys.
// Constructs the evaluator cannot enforce fail closed: an Allow carrying one is
// treated as non-matching, a Deny as matching, so an unenforced restriction can
// only narrow access, never widen it.
func (s *Statement) matches(action, resource string, keys ConditionKeys) bool {
	if operator, key, found := s.unenforceable(); found {
		slog.Warn("iampolicy: statement carries a construct this release does not enforce, failing closed",
			"sid", s.Sid, "effect", s.Effect, "action", action,
			"operator", operator, "key", key)
		if s.Effect == EffectAllow {
			return false
		}

		// Deny, and unrecognized effects, fall through so the caller's Effect
		// switch still fires. NotAction/NotResource leave the corresponding
		// positive selector empty, so that half is treated as matching.
		return (len(s.NotAction) > 0 || matchesAny(s.Action, action, true)) &&
			(len(s.NotResource) > 0 || matchesAnyResource(s.Resource, resource, keys))
	}

	return matchesAny(s.Action, action, true) &&
		matchesAnyResource(s.Resource, resource, keys) &&
		s.conditionsHold(keys)
}

// unenforceable returns the first construct on the statement that this release
// cannot evaluate, for the fail-closed warning. NotAction, NotResource and
// Principal report themselves in the operator position; they have no key.
func (s *Statement) unenforceable() (operator, key string, found bool) {
	if len(s.NotAction) > 0 {
		return "NotAction", "", true
	}
	if len(s.NotResource) > 0 {
		return "NotResource", "", true
	}
	// A JSON null counts as absent, so a document that merely spells the field
	// out is not forced down the fail-closed path.
	if p := bytes.TrimSpace(s.Principal); len(p) > 0 && !bytes.Equal(p, []byte("null")) {
		return "Principal", "", true
	}
	for op, byKey := range s.Condition {
		for k := range byKey {
			if !SupportedCondition(op, k) {
				return op, k, true
			}
		}
	}
	return "", "", false
}
