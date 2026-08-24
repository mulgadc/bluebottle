package iampolicy

import (
	"net/netip"
	"slices"
	"strings"
)

// Condition context keys understood by the evaluator. Anything outside this set
// fails closed; the write path rejects it outright.
const (
	// KeySourceIP is the caller's source address, compared with IpAddress.
	KeySourceIP = "aws:SourceIp"
	// KeyS3Prefix is the S3 listing prefix. Only the S3 data plane supplies it.
	KeyS3Prefix = "s3:prefix"
	// KeySecureTransport reports whether the request arrived over TLS.
	KeySecureTransport = "aws:SecureTransport"
	// KeyUsername is the authenticated principal's user name.
	KeyUsername = "aws:username"
	// KeyPrincipalAccount is the authenticated principal's account ID.
	KeyPrincipalAccount = "aws:PrincipalAccount"
)

// Condition operators understood by the evaluator.
const (
	OpStringEquals = "StringEquals"
	OpStringLike   = "StringLike"
	OpIPAddress    = "IpAddress"
	OpBool         = "Bool"
)

// supportedConditions maps each condition key to the operators the evaluator
// implements for it. aws:MultiFactorAuthPresent is deliberately absent: spinifex
// has no MFA, so the key could never be true and accepting it would mint a grant
// that silently never fires.
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
// absent key evaluates its condition false, so "absent" must stay distinguishable
// from "present but empty" — a policy written for one data plane's keys therefore
// simply does not fire on another's.
type ConditionKeys map[string]string

// conditionsHold reports whether every condition block on the statement is
// satisfied. Blocks and keys are ANDed; the values within one key are ORed, as
// AWS specifies.
func (s *Statement) conditionsHold(keys ConditionKeys) bool {
	for op, byKey := range s.Condition {
		for key, values := range byKey {
			actual, present := keys[key]
			if !present || !conditionHolds(op, actual, values) {
				return false
			}
		}
	}
	return true
}

// conditionHolds applies one operator to the request's value for a key. An
// unrecognized operator returns false; callers reject those before reaching here.
func conditionHolds(operator, actual string, values []string) bool {
	switch operator {
	case OpStringEquals:
		return slices.Contains(values, actual)
	case OpBool:
		for _, v := range values {
			if strings.EqualFold(v, actual) {
				return true
			}
		}
	case OpStringLike:
		for _, v := range values {
			if MatchWildcard(v, actual) {
				return true
			}
		}
	case OpIPAddress:
		return ipInAny(actual, values)
	}
	return false
}

// ipInAny reports whether actual falls inside any of the CIDR blocks or equals
// any of the bare addresses in values. An unparseable address matches nothing.
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
		if other, err := netip.ParseAddr(v); err == nil && other.Unmap() == addr {
			return true
		}
	}
	return false
}
