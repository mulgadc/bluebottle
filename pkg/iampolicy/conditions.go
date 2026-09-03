package iampolicy

import (
	"log/slog"
	"net/netip"
	"strings"
)

// Condition context keys understood by the evaluator. Only the S3 data plane
// supplies KeyS3Prefix.
const (
	KeySourceIP         = "aws:SourceIp"
	KeyS3Prefix         = "s3:prefix"
	KeySecureTransport  = "aws:SecureTransport"
	KeyUsername         = "aws:username"
	KeyPrincipalAccount = "aws:PrincipalAccount"
	KeyUserID           = "aws:userid"
)

// Condition operators understood by the evaluator.
const (
	OpStringEquals = "StringEquals"
	OpStringLike   = "StringLike"
	OpIPAddress    = "IpAddress"
	OpBool         = "Bool"
)

// aws:MultiFactorAuthPresent is deliberately absent: there is no MFA anywhere in
// the stack, so the key could never be true and accepting it would mint a grant
// that silently never fires. KeyUserID is absent for a different reason: no
// operator over it is implemented, so it is substitutable as a ${...} reference
// but not yet usable in a condition.
var supportedConditions = map[string]map[string]bool{
	KeySourceIP:         {OpIPAddress: true},
	KeyS3Prefix:         {OpStringEquals: true, OpStringLike: true},
	KeySecureTransport:  {OpBool: true},
	KeyUsername:         {OpStringEquals: true},
	KeyPrincipalAccount: {OpStringEquals: true},
}

// SupportedCondition reports whether the evaluator enforces operator on key.
// Write paths gate on this so the front door never accepts a condition the
// evaluator would fail closed on.
func SupportedCondition(operator, key string) bool {
	return supportedConditions[key][operator]
}

// ConditionKeys carries the condition context keys resolved for one request. An
// absent key evaluates its condition false, so absent must stay distinguishable
// from present-but-empty.
type ConditionKeys map[string]string

// conditionsHold reports whether every condition block on the statement is
// satisfied. Blocks and keys are ANDed, values within one key ORed, per AWS.
//
// A value carrying a policy variable this door cannot resolve takes failClosed,
// so a Deny survives one rather than disappearing.
func (s *Statement) conditionsHold(keys ConditionKeys, failClosed bool) bool {
	for op, byKey := range s.Condition {
		for key, values := range byKey {
			actual, present := keys[key]
			if !present || !conditionHolds(op, actual, values, keys, failClosed) {
				return false
			}
		}
	}
	return true
}

// conditionHolds applies one operator to the request's value for a key. An
// unrecognized operator returns false; callers reject those before reaching here.
//
// keys resolves policy variables in the string operators' values. Bool and
// IpAddress values are compared as written, a variable in either having no
// meaning. A value carrying an unresolvable reference takes failClosed.
func conditionHolds(operator, actual string, values []string, keys ConditionKeys, failClosed bool) bool {
	switch operator {
	case OpStringEquals:
		for _, v := range values {
			// Values are ORed, so an unresolvable one must not cut the scan short.
			switch resolved, result := expandVariables(v, keys, false); {
			case result == expansionUnresolvable:
				slog.Debug("iampolicy: policy variable is unresolvable at this door",
					"value", v, "matches", failClosed)
				if failClosed {
					return true
				}
			case resolved == actual:
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
		return ipInAny(actual, values)
	}
	return false
}

// ipInAny reports whether actual falls inside any CIDR block or equals any bare
// address in values. An unparseable address matches nothing, and an unparseable
// policy value warns: write paths reject those, so one here predates the fix.
func ipInAny(actual string, values []string) bool {
	addr, err := netip.ParseAddr(actual)
	if err != nil {
		return false
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
