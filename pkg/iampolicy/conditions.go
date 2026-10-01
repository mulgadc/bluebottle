package iampolicy

import (
	"log/slog"
	"net/netip"
	"strings"
)

// Condition context keys understood by the evaluator. Only the S3 data plane
// supplies KeyS3Prefix, and only an iam:PassRole check supplies KeyPassedToService.
const (
	KeySourceIP         = "aws:SourceIp"
	KeyS3Prefix         = "s3:prefix"
	KeySecureTransport  = "aws:SecureTransport"
	KeyUsername         = "aws:username"
	KeyPrincipalAccount = "aws:PrincipalAccount"
	KeyUserID           = "aws:userid"
	KeyPrincipalType    = "aws:PrincipalType"
	KeyPassedToService  = "iam:PassedToService"
)

// Canonical aws:PrincipalType values, spelled exactly as AWS documents them.
// Both doors map their internal principal-type strings through these so a
// policy sees one spelling regardless of which door resolved it.
const (
	PrincipalTypeUser          = "User"
	PrincipalTypeAssumedRole   = "AssumedRole"
	PrincipalTypeAccount       = "Account"
	PrincipalTypeFederatedUser = "FederatedUser"
	PrincipalTypeAnonymous     = "Anonymous"
)

// Condition operators understood by the evaluator.
const (
	OpStringEquals              = "StringEquals"
	OpStringNotEquals           = "StringNotEquals"
	OpStringEqualsIgnoreCase    = "StringEqualsIgnoreCase"
	OpStringNotEqualsIgnoreCase = "StringNotEqualsIgnoreCase"
	OpStringLike                = "StringLike"
	OpStringNotLike             = "StringNotLike"
	OpIPAddress                 = "IpAddress"
	OpNotIPAddress              = "NotIpAddress"
	OpBool                      = "Bool"
	OpArnEquals                 = "ArnEquals"
	OpArnLike                   = "ArnLike"
	OpArnNotEquals              = "ArnNotEquals"
	OpArnNotLike                = "ArnNotLike"
	OpNull                      = "Null"
)

// IfExistsSuffix turns any operator but Null into one that holds on a key absent
// from the request context and otherwise evaluates as its base operator.
const IfExistsSuffix = "IfExists"

// negatedOperators maps each negated operator to the positive form it inverts.
// Per AWS, a negated operator holds on a key absent from the request context.
var negatedOperators = map[string]string{
	OpStringNotEquals:           OpStringEquals,
	OpStringNotEqualsIgnoreCase: OpStringEqualsIgnoreCase,
	OpStringNotLike:             OpStringLike,
	OpNotIPAddress:              OpIPAddress,
	OpArnNotEquals:              OpArnEquals,
	OpArnNotLike:                OpArnLike,
}

// Operator sets for the registry below. Each string key carries the negated and
// case-insensitive forms of the operators it supports. The Arn operators are on
// no key: none of the supported keys is ARN-valued.
var (
	stringEqualsOps = []string{OpStringEquals, OpStringNotEquals, OpStringEqualsIgnoreCase, OpStringNotEqualsIgnoreCase}
	stringLikeOps   = []string{OpStringLike, OpStringNotLike}
)

func operators(sets ...[]string) map[string]bool {
	ops := make(map[string]bool)
	for _, set := range sets {
		for _, op := range set {
			ops[op] = true
		}
	}
	return ops
}

// aws:MultiFactorAuthPresent is deliberately absent: there is no MFA anywhere in
// the stack, so the key could never be true and accepting it would mint a grant
// that silently never fires.
var supportedConditions = map[string]map[string]bool{
	KeySourceIP:         {OpIPAddress: true, OpNotIPAddress: true},
	KeyS3Prefix:         operators(stringEqualsOps, stringLikeOps),
	KeySecureTransport:  {OpBool: true},
	KeyUsername:         operators(stringEqualsOps),
	KeyPrincipalAccount: operators(stringEqualsOps),
	// Unlike aws:username this is safe for every principal type: neither a
	// user's unique ID nor the role ID and session name STS mints is
	// caller-chosen, so a role session cannot satisfy it at will.
	KeyUserID: operators(stringEqualsOps, stringLikeOps),
	// Not caller-chosen: both doors resolve it from the credential record, not
	// from anything the request carries, so it clears the bar aws:username
	// fails for role sessions.
	KeyPrincipalType: operators(stringEqualsOps, stringLikeOps),
	// Fixed by the service performing the PassRole check, never read from the
	// request, and absent on every other action.
	KeyPassedToService: operators(stringEqualsOps, stringLikeOps),
}

// SupportedCondition reports whether the evaluator enforces operator on key.
// Write paths gate on this so the front door never accepts a condition the
// evaluator would fail closed on.
//
// An IfExists form is supported exactly where its base operator is, and Null on
// every registered key, so neither needs entries of its own that could drift.
func SupportedCondition(operator, key string) bool {
	base, ifExists := BaseOperator(operator)
	if base == OpNull {
		_, registered := supportedConditions[key]
		return registered && !ifExists
	}
	return supportedConditions[key][base]
}

// BaseOperator strips the IfExists suffix from operator, reporting whether it
// was there. The evaluator and write paths read every operator through it.
func BaseOperator(operator string) (base string, ifExists bool) {
	return strings.CutSuffix(operator, IfExistsSuffix)
}

// ConditionKeys carries the condition context keys resolved for one request. An
// absent key evaluates its condition false, or true under a negated, IfExists or
// Null-true operator, so absent must stay distinguishable from present-but-empty.
type ConditionKeys map[string]string

// conditionsHold reports whether every condition block on the statement is
// satisfied. Blocks and keys are ANDed, values within one key ORed, per AWS.
//
// A value carrying a policy variable this door cannot resolve takes failClosed,
// so a Deny survives one rather than disappearing. An absent key holds only
// under a negated or IfExists operator, so omitting it cannot stop either firing.
func (s *Statement) conditionsHold(keys ConditionKeys, failClosed bool) bool {
	for op, byKey := range s.Condition {
		base, ifExists := BaseOperator(op)
		_, negated := negatedOperators[base]
		for key, values := range byKey {
			actual, present := keys[key]
			if base == OpNull {
				if !nullHolds(present, values) {
					return false
				}
				continue
			}
			if !present {
				if negated || ifExists {
					continue
				}
				return false
			}
			if !conditionHolds(base, actual, values, keys, failClosed) {
				return false
			}
		}
	}
	return true
}

// conditionHolds applies one operator to the request's value for a key. An
// unrecognized operator returns false; callers reject those before reaching here.
//
// keys resolves policy variables in the string and ARN operators' values. Bool
// and IpAddress values are compared as written, a variable in either having no
// meaning. A value carrying an unresolvable reference takes failClosed.
func conditionHolds(operator, actual string, values []string, keys ConditionKeys, failClosed bool) bool {
	// Inverting failClosed inside the match keeps an unresolvable value narrowing
	// access after the negation, as NotResource does.
	if positive, negated := negatedOperators[operator]; negated {
		return !conditionHolds(positive, actual, values, keys, !failClosed)
	}

	switch operator {
	case OpStringEquals:
		return equalsAny(actual, values, keys, failClosed, false)
	case OpStringEqualsIgnoreCase:
		return equalsAny(actual, values, keys, failClosed, true)
	case OpArnEquals, OpArnLike:
		for _, v := range values {
			if matchARN(v, actual, keys, failClosed) {
				return true
			}
		}
	case OpBool:
		for _, v := range values {
			if strings.EqualFold(v, actual) {
				return true
			}
		}
	case OpStringLike:
		for _, v := range values {
			if matchPattern(v, actual, keys, failClosed) {
				return true
			}
		}
	case OpIPAddress:
		return ipInAny(actual, values, failClosed)
	}
	return false
}

// nullHolds applies Null: true holds on an absent key, false on a present one,
// and values are ORed. Anything else matches nothing; write paths reject it.
func nullHolds(present bool, values []string) bool {
	for _, v := range values {
		if (strings.EqualFold(v, "true") && !present) || (strings.EqualFold(v, "false") && present) {
			return true
		}
	}
	return false
}

// equalsAny reports whether actual equals any value after resolving its policy
// variables, folding case when fold is true. A value carrying an unresolvable
// reference takes failClosed.
func equalsAny(actual string, values []string, keys ConditionKeys, failClosed, fold bool) bool {
	for _, v := range values {
		// Values are ORed, so an unresolvable one must not cut the scan short.
		resolved, result := expandVariables(v, keys, false)
		switch {
		case result == expansionUnresolvable:
			slog.Debug("iampolicy: policy variable is unresolvable at this door",
				"value", v, "matches", failClosed)
			if failClosed {
				return true
			}
		case fold && strings.EqualFold(resolved, actual), !fold && resolved == actual:
			return true
		}
	}
	return false
}

// ipInAny reports whether actual falls inside any CIDR block or equals any bare
// address in values. An unparseable request address takes failClosed, as every
// other operator does with input it cannot resolve, and warns either way.
func ipInAny(actual string, values []string, failClosed bool) bool {
	addr, err := netip.ParseAddr(actual)
	if err != nil {
		// A door passing host:port rather than a bare host is the likely cause.
		slog.Warn("iampolicy: request address is not an address, so the condition cannot compare",
			"address", actual, "key", KeySourceIP, "matches", failClosed)
		return failClosed
	}
	addr = addr.Unmap()
	for _, v := range values {
		if prefix, err := netip.ParsePrefix(v); err == nil {
			if prefix.Masked().Contains(addr) {
				return true
			}
			continue
		}
		other, err := netip.ParseAddr(v)
		if err != nil {
			slog.Warn("iampolicy: IpAddress condition value is not an address or CIDR block, matching nothing",
				"value", v, "key", KeySourceIP)
			continue
		}
		if other.Unmap() == addr {
			return true
		}
	}
	return false
}
