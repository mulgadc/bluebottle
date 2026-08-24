package iampolicy

import "log/slog"

// Decision represents the outcome of a policy evaluation.
type Decision int

const (
	// Deny is the default — no matching Allow, or an explicit Deny.
	Deny Decision = iota
	// Allow means an explicit Allow was found with no overriding Deny.
	Allow
)

// Evaluate reports whether action on resource is permitted by the supplied
// policy documents, following AWS's evaluation order:
//
//  1. Explicit Deny in any statement → Deny (wins immediately).
//  2. Explicit Allow in any statement → Allow.
//  3. No matching statement → Deny (implicit default).
//
// Actions match case-insensitively (AWS lower-cases service:verb); resource
// ARNs match case-sensitively (AWS spec). An unrecognized Effect fails closed to
// Deny with a warning. Root bypass, if any, is handled by the caller.
// Conditions are evaluated against no context keys, so any statement carrying
// one fails closed. Callers that can supply keys use EvaluateWithKeys.
func Evaluate(action, resource string, policies []PolicyDocument) Decision {
	return EvaluateWithKeys(action, resource, policies, nil)
}

// EvaluateWithKeys is Evaluate with the request's condition context keys. A
// condition on a key the caller cannot supply evaluates false, per AWS, so the
// same policy legitimately gives different answers at different doors.
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
				slog.Warn("iampolicy.Evaluate: unrecognized Effect, treating as Deny",
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
			(len(s.NotResource) > 0 || matchesAny(s.Resource, resource, false))
	}

	return matchesAny(s.Action, action, true) &&
		matchesAny(s.Resource, resource, false) &&
		s.conditionsHold(keys)
}

// unenforceable returns the first construct on the statement that this release
// cannot evaluate, for the fail-closed warning. NotAction and NotResource report
// themselves in the operator position; they have no key.
func (s *Statement) unenforceable() (operator, key string, found bool) {
	if len(s.NotAction) > 0 {
		return "NotAction", "", true
	}
	if len(s.NotResource) > 0 {
		return "NotResource", "", true
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
