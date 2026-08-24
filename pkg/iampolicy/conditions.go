package iampolicy

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
