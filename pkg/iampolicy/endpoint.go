package iampolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// EvaluateEndpointPolicy decides action on resource under a VPC endpoint policy,
// the second gate on a request through an endpoint, as EvaluateWithKeys does an
// identity policy. Parse the document with ParseEndpointPolicy.
func EvaluateEndpointPolicy(action, resource string, policy PolicyDocument, keys ConditionKeys) Decision {
	return evaluate(action, resource, []PolicyDocument{policy}, keys, endpointMode)
}

// ParseEndpointPolicy reads an endpoint policy as AWS does: Statement may be one
// object or an array, and a condition key's case does not matter, so each
// registered key is rewritten to the spelling the request context uses.
func ParseEndpointPolicy(raw []byte) (PolicyDocument, error) {
	var doc struct {
		Version   string          `json:"Version"`
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return PolicyDocument{}, err
	}
	out := PolicyDocument{Version: doc.Version}
	body := bytes.TrimSpace(doc.Statement)
	switch {
	case len(body) == 0 || bytes.Equal(body, []byte("null")):
	case body[0] == '{':
		var one Statement
		if err := json.Unmarshal(body, &one); err != nil {
			return PolicyDocument{}, err
		}
		out.Statement = []Statement{one}
	default:
		if err := json.Unmarshal(body, &out.Statement); err != nil {
			return PolicyDocument{}, err
		}
	}
	for i := range out.Statement {
		out.Statement[i].Condition = canonicalKeys(out.Statement[i].Condition)
	}
	return out, nil
}

// canonicalKeys respells each condition key that names a registered key in
// another case. Two spellings of one key in a block are merged, as one key.
func canonicalKeys(conditions map[string]map[string]ConditionValue) map[string]map[string]ConditionValue {
	for op, byKey := range conditions {
		respelled := make(map[string]ConditionValue, len(byKey))
		for key, values := range byKey {
			name := canonicalKey(key)
			respelled[name] = append(respelled[name], values...)
		}
		conditions[op] = respelled
	}
	return conditions
}

func canonicalKey(key string) string {
	for _, registry := range []map[string]map[string]bool{supportedConditions, endpointConditions} {
		for name := range registry {
			if strings.EqualFold(name, key) {
				return name
			}
		}
	}
	return key
}

// CheckEndpointPolicy reports the first statement EvaluateEndpointPolicy would
// not enforce as written, so a write path can refuse a policy rather than store
// one that fails closed.
func CheckEndpointPolicy(policy PolicyDocument) error {
	statements := policy.Statement
	if policy.Version != Version2012 {
		statements = literalVariableStatements(statements)
	}
	for i := range statements {
		s := &statements[i]
		if s.Effect != EffectAllow && s.Effect != EffectDeny {
			return fmt.Errorf("statement %d: Effect %q is not Allow or Deny", i, s.Effect)
		}
		if !s.wellFormedActions() || !s.wellFormedResources() {
			operator, _, _ := s.unenforceable(endpointMode)
			return fmt.Errorf("statement %d: %s is not supported", i, operator)
		}
		if _, _, fault := s.endpointFault(); fault != "" {
			return fmt.Errorf("statement %d: %s", i, fault)
		}
	}
	return nil
}

// endpointUnenforceable is unenforceable for an endpoint policy: a Principal the
// gate can match, conditions it enforces with operands it can read, and policy
// variables it can resolve.
func (s *Statement) endpointUnenforceable() (operator, key string, found bool) {
	operator, key, fault := s.endpointFault()
	return operator, key, fault != ""
}

// endpointFault names the first construct of an endpoint statement the gate
// cannot enforce, with the reason a write path reports, or "" if there is none.
func (s *Statement) endpointFault() (operator, key, fault string) {
	if _, ok := endpointPrincipals(s.Principal); !ok {
		return "Principal", "", "Principal must be \"*\" or name AWS accounts, IAM users or IAM roles"
	}
	for _, values := range [][]string{s.Resource, s.NotResource} {
		for _, v := range values {
			if ref, bad := UnsupportedVariable(v); bad {
				return "Resource", ref, fmt.Sprintf("Resource %q has a policy variable that cannot be resolved", v)
			}
		}
	}
	for op, byKey := range s.Condition {
		if len(byKey) == 0 {
			return op, "", fmt.Sprintf("condition %s names no key", op)
		}
		base, _ := BaseOperator(op)
		for k, values := range byKey {
			switch {
			case !SupportedEndpointCondition(op, k):
				return op, k, fmt.Sprintf("condition %s on %s is not supported", op, k)
			case len(values) == 0:
				return op, k, fmt.Sprintf("condition %s on %s has no value", op, k)
			}
			for _, v := range values {
				if base == OpNull && !strings.EqualFold(v, "true") && !strings.EqualFold(v, "false") {
					return op, k, fmt.Sprintf("condition Null on %s takes true or false", k)
				}
				if _, bad := UnsupportedVariable(v); bad && substitutesValues(base) {
					return op, k, fmt.Sprintf("condition %s on %s has a policy variable that cannot be resolved", op, k)
				}
			}
		}
	}
	return "", "", ""
}

// substitutesValues reports whether operator resolves policy variables in its
// values, as conditionHolds does for the string and ARN operators.
func substitutesValues(operator string) bool {
	if positive, negated := negatedOperators[operator]; negated {
		operator = positive
	}
	switch operator {
	case OpStringEquals, OpStringEqualsIgnoreCase, OpStringLike, OpArnEquals, OpArnLike:
		return true
	}
	return false
}

// accountID is a bare account ID, which AWS accepts as a principal and reads as
// the account's root.
var accountID = regexp.MustCompile(`^[0-9]{12}$`)

// iamARN is a principal ARN the gate can compare with aws:PrincipalArn: an
// account root, or an IAM user or role.
var iamARN = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):(root|user/.+|role/.+)$`)

// endpointPrincipals returns the AWS principals a Principal element names, or
// "*" for every caller, and false for a form the gate cannot match: none, a
// service or federated principal, or an ARN that is not an IAM user, role or root.
func endpointPrincipals(raw []byte) ([]string, bool) {
	raw = bytes.TrimSpace(raw)
	var star string
	if json.Unmarshal(raw, &star) == nil {
		return []string{star}, star == "*"
	}
	var byType map[string]StringOrArr
	if json.Unmarshal(raw, &byType) != nil || len(byType) != 1 {
		return nil, false
	}
	names, ok := byType["AWS"]
	if !ok || len(names) == 0 {
		return nil, false
	}
	for _, n := range names {
		if n != "*" && !accountID.MatchString(n) && !iamARN.MatchString(n) {
			return nil, false
		}
	}
	return names, true
}

// matchesPrincipal reports whether the caller is one the statement names. An
// account or root names every principal in the account, and a user or role ARN
// the principal whose aws:PrincipalArn it is. A key the door did not supply
// takes failClosed.
func (s *Statement) matchesPrincipal(keys ConditionKeys, failClosed bool) bool {
	names, _ := endpointPrincipals(s.Principal)
	for _, n := range names {
		if n == "*" {
			return true
		}
		account, isAccount := n, accountID.MatchString(n)
		if m := iamARN.FindStringSubmatch(n); m != nil && m[2] == "root" {
			account, isAccount = m[1], true
		}
		want, have := keys[KeyPrincipalArn]
		if isAccount {
			want, have = keys[KeyPrincipalAccount]
			n = account
		}
		if !have {
			if failClosed {
				return true
			}
			continue
		}
		if want == n {
			return true
		}
	}
	return false
}
