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
// caller cannot supply evaluates false, or true under a negated operator, per
// AWS, so the same policy legitimately gives different answers at different
// doors. Passing nil fails every condition except the negated ones, which hold.
//
// Resource patterns and string condition values may carry ${key} policy
// variables, resolved from keys. An unresolvable one fails closed: it makes an
// Allow non-matching and a Deny matching, so it can only narrow access.
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
	// The same rule covers a policy variable this door cannot supply: an Allow
	// carrying one selects nothing, a Deny selects everything it might have.
	failClosed := s.Effect != EffectAllow

	if operator, key, found := s.unenforceable(); found {
		slog.Warn("iampolicy: statement carries a construct this release does not enforce, failing closed",
			"sid", s.Sid, "effect", s.Effect, "action", action,
			"operator", operator, "key", key)
		if s.Effect == EffectAllow {
			return false
		}

		// Deny, and unrecognized effects, fall through so the caller's Effect
		// switch still fires. A malformed selector pair is treated as matching
		// on that half, since it cannot be read as a narrower statement.
		return (!s.wellFormedActions() || s.matchesAction(action)) &&
			(!s.wellFormedResources() || s.matchesResource(resource, keys, failClosed))
	}

	return s.matchesAction(action) &&
		s.matchesResource(resource, keys, failClosed) &&
		s.conditionsHold(keys, failClosed)
}

// matchesAction selects on Action, or on the complement of NotAction.
func (s *Statement) matchesAction(action string) bool {
	if len(s.NotAction) > 0 {
		return !matchesAny(s.NotAction, action, true)
	}
	return matchesAny(s.Action, action, true)
}

// matchesResource selects on Resource, or on the complement of NotResource. An
// unresolvable variable in NotResource takes the inverted fail-closed value, so
// after the complement it still only narrows access.
func (s *Statement) matchesResource(resource string, keys ConditionKeys, failClosed bool) bool {
	if len(s.NotResource) > 0 {
		return !matchesAnyResource(s.NotResource, resource, keys, !failClosed)
	}
	return matchesAnyResource(s.Resource, resource, keys, failClosed)
}

// wellFormedActions reports whether Action and NotAction are not both set, as
// AWS requires. A statement with neither selects nothing, so needs no check.
// wellFormedResources is the same rule for resources.
func (s *Statement) wellFormedActions() bool {
	return len(s.Action) == 0 || len(s.NotAction) == 0
}

func (s *Statement) wellFormedResources() bool {
	return len(s.Resource) == 0 || len(s.NotResource) == 0
}

// unenforceable returns the first construct on the statement that this release
// cannot evaluate, for the fail-closed warning. A malformed selector pair and
// Principal report themselves in the operator position; they have no key.
func (s *Statement) unenforceable() (operator, key string, found bool) {
	if !s.wellFormedActions() {
		return "Action/NotAction", "", true
	}
	if !s.wellFormedResources() {
		return "Resource/NotResource", "", true
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
