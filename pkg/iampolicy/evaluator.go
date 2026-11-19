package iampolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
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
// caller cannot supply evaluates false, or true under a negated, IfExists or
// Null-true operator, per AWS, so the same policy legitimately gives different
// answers at different doors. Passing nil makes every key absent.
//
// Resource patterns and string condition values may carry ${key} policy
// variables, resolved from keys. An unresolvable one fails closed: it makes an
// Allow non-matching and a Deny matching, so it can only narrow access. In a
// document not written in Version2012, ${...} is literal text, as in AWS.
func EvaluateWithKeys(action, resource string, policies []PolicyDocument, keys ConditionKeys) Decision {
	return evaluate(action, resource, policies, keys, identityMode)
}

// EvaluateEndpointPolicy decides action on resource under a VPC endpoint policy,
// the second gate on a request through an endpoint, as EvaluateWithKeys does an
// identity policy. Principal "*" and {"AWS":"*"} select every caller there, and
// aws:PrincipalArn is enforced; any other Principal, or none, fails closed.
func EvaluateEndpointPolicy(action, resource string, policy PolicyDocument, keys ConditionKeys) Decision {
	return evaluate(action, resource, []PolicyDocument{policy}, keys, endpointMode)
}

// CheckEndpointPolicy reports the first statement EvaluateEndpointPolicy would
// not enforce as written, so a write path can refuse a policy rather than store
// one that fails closed.
func CheckEndpointPolicy(policy PolicyDocument) error {
	for i := range policy.Statement {
		s := &policy.Statement[i]
		if s.Effect != EffectAllow && s.Effect != EffectDeny {
			return fmt.Errorf("statement %d: Effect %q is not Allow or Deny", i, s.Effect)
		}
		if operator, key, found := s.unenforceable(endpointMode); found {
			if key == "" {
				return fmt.Errorf("statement %d: %s is not supported", i, operator)
			}
			return fmt.Errorf("statement %d: condition %s on %s is not supported", i, operator, key)
		}
	}
	return nil
}

// mode selects what a statement may carry: an identity policy has no Principal,
// and an endpoint policy must name every principal.
type mode int

const (
	identityMode mode = iota
	endpointMode
)

func evaluate(action, resource string, policies []PolicyDocument, keys ConditionKeys, m mode) Decision {
	hasAllow := false
	for i := range policies {
		statements := policies[i].Statement
		if policies[i].Version != Version2012 {
			statements = literalVariableStatements(statements)
		}
		for j := range statements {
			stmt := &statements[j]

			if !stmt.matches(action, resource, keys, m) {
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
func (s *Statement) matches(action, resource string, keys ConditionKeys, m mode) bool {
	// The same rule covers a policy variable this door cannot supply: an Allow
	// carrying one selects nothing, a Deny selects everything it might have.
	failClosed := s.Effect != EffectAllow

	if operator, key, found := s.unenforceable(m); found {
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
func (s *Statement) unenforceable(m mode) (operator, key string, found bool) {
	if !s.wellFormedActions() {
		return "Action/NotAction", "", true
	}
	if !s.wellFormedResources() {
		return "Resource/NotResource", "", true
	}
	// A JSON null counts as absent, so a document that merely spells the field
	// out is not forced down the fail-closed path.
	p := bytes.TrimSpace(s.Principal)
	absent := len(p) == 0 || bytes.Equal(p, []byte("null"))
	if (m == identityMode && !absent) || (m == endpointMode && !everyPrincipal(p)) {
		return "Principal", "", true
	}
	supported := SupportedCondition
	if m == endpointMode {
		supported = SupportedEndpointCondition
	}
	for op, byKey := range s.Condition {
		for k := range byKey {
			if !supported(op, k) {
				return op, k, true
			}
		}
	}
	return "", "", false
}

// everyPrincipal reports whether a Principal element names every caller: "*",
// or an AWS principal of "*" alone, the forms an endpoint policy may use.
func everyPrincipal(raw []byte) bool {
	var star string
	if json.Unmarshal(raw, &star) == nil {
		return star == "*"
	}
	var byType map[string]json.RawMessage
	if json.Unmarshal(raw, &byType) != nil || len(byType) != 1 {
		return false
	}
	aws, ok := byType["AWS"]
	if !ok {
		return false
	}
	if json.Unmarshal(aws, &star) == nil {
		return star == "*"
	}
	var list []string
	return json.Unmarshal(aws, &list) == nil && len(list) == 1 && list[0] == "*"
}
