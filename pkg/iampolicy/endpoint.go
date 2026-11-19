package iampolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
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
		return "Principal", "", "Principal must be \"*\" or name AWS accounts; name users and roles with aws:PrincipalArn"
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
				if !readableOperand(base, v) {
					return op, k, fmt.Sprintf("condition %s on %s cannot compare with %q", op, k, v)
				}
				if _, bad := UnsupportedVariable(v); bad && substitutesValues(base) {
					return op, k, fmt.Sprintf("condition %s on %s has a policy variable that cannot be resolved", op, k)
				}
			}
		}
	}
	return "", "", ""
}

// readableOperand reports whether the matcher can compare with v under
// operator, which otherwise reads v as matching nothing and so could drop a Deny.
func readableOperand(operator, v string) bool {
	if positive, negated := negatedOperators[operator]; negated {
		operator = positive
	}
	switch operator {
	case OpNull, OpBool:
		return strings.EqualFold(v, "true") || strings.EqualFold(v, "false")
	case OpIPAddress:
		if _, err := netip.ParsePrefix(v); err == nil {
			return true
		}
		_, err := netip.ParseAddr(v)
		return err == nil
	case OpDateEquals, OpDateLessThan, OpDateLessThanEquals, OpDateGreaterThan, OpDateGreaterThanEquals:
		_, err := ParseDate(v)
		return err == nil
	case OpNumericEquals, OpNumericLessThan, OpNumericLessThanEquals, OpNumericGreaterThan, OpNumericGreaterThanEquals:
		_, err := ParseNumber(v)
		return err == nil
	}
	return true
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
// the account's root user.
var accountID = regexp.MustCompile(`^[0-9]{12}$`)

// rootARN names an account's root user.
var rootARN = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):root$`)

// endpointPrincipals returns the accounts a Principal element names, or "*" for
// every caller, and false for a form a gateway endpoint gives no meaning: none,
// a service or federated principal, or an IAM user, role or session ARN.
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
	accounts := make([]string, 0, len(names))
	for _, n := range names {
		if m := rootARN.FindStringSubmatch(n); m != nil {
			n = m[1]
		}
		if n != "*" && !accountID.MatchString(n) {
			return nil, false
		}
		accounts = append(accounts, n)
	}
	return accounts, true
}

// matchesPrincipal reports whether the caller is one the statement names. On a
// gateway endpoint an account names its root user only, as AWS documents; a
// caller the door does not describe takes failClosed.
func (s *Statement) matchesPrincipal(keys ConditionKeys, failClosed bool) bool {
	accounts, _ := endpointPrincipals(s.Principal)
	for _, account := range accounts {
		if account == "*" {
			return true
		}
		principalType, typed := keys[KeyPrincipalType]
		caller, known := keys[KeyPrincipalAccount]
		if !typed || !known {
			if failClosed {
				return true
			}
			continue
		}
		if principalType == PrincipalTypeAccount && caller == account {
			return true
		}
	}
	return false
}
