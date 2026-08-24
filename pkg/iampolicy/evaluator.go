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
func Evaluate(action, resource string, policies []PolicyDocument) Decision {
	hasAllow := false
	for i := range policies {
		for j := range policies[i].Statement {
			stmt := &policies[i].Statement[j]

			if !stmt.matches(action, resource) {
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

// matches reports whether the statement selects action on resource. Constructs
// the evaluator cannot enforce fail closed: an Allow carrying one is treated as
// non-matching, a Deny as matching, so an unenforced restriction can only narrow
// access, never widen it.
func (s *Statement) matches(action, resource string) bool {
	if !s.unenforceable() {
		return matchesAny(s.Action, action, true) && matchesAny(s.Resource, resource, false)
	}

	slog.Warn("iampolicy.Evaluate: statement carries constructs this release does not enforce, failing closed",
		"sid", s.Sid, "effect", s.Effect, "action", action)
	if s.Effect == EffectAllow {
		return false
	}

	// Deny, and unrecognized effects, fall through so the caller's Effect switch
	// still fires. NotAction/NotResource leave the corresponding positive
	// selector empty, so that half is treated as matching.
	return (len(s.NotAction) > 0 || matchesAny(s.Action, action, true)) &&
		(len(s.NotResource) > 0 || matchesAny(s.Resource, resource, false))
}

// unenforceable reports whether the statement carries a construct outside what
// this release evaluates.
func (s *Statement) unenforceable() bool {
	return len(s.Condition) > 0 || len(s.NotAction) > 0 || len(s.NotResource) > 0
}
