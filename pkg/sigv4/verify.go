package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/aws/smithy-go/encoding/httpbinding"
)

const (
	redactedValue  = "<redacted>"
	amzSessionName = "x-amz-security-token"
)

// Verify checks the request signature under secretAccessKey and confirms the credential
// scope's region and service match region and service, returning a VerifiedRequest when
// the request is authentic. region is the region the caller requires the client to have
// signed with, which is not necessarily the endpoint's own.
func (req *SignedRequest) Verify(secretAccessKey, region, service string) (*VerifiedRequest, error) {
	// Ensure client region and service match the caller's expected values.
	if req.Credential.Region != region {
		return nil, fmt.Errorf("%w: incorrect region %q; expected %q", ErrMalformedAuthorization, req.Credential.Region, region)
	} else if req.Credential.Service != service {
		return nil, fmt.Errorf("%w: incorrect service %q; expected %q", ErrMalformedAuthorization, req.Credential.Service, service)
	}

	stringToSign := req.buildStringToSign()
	signingKey := req.buildSigningKey(secretAccessKey)

	// Constant-time compare our signature against the one the client provided.
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	if !hmac.Equal([]byte(signature), []byte(req.Signature)) {
		return nil, ErrSignatureMismatch
	}

	// The signature covers the declared payload hash; binding makes it cover the body too.
	if err := req.bindPayload(); err != nil {
		return nil, err
	}

	return &VerifiedRequest{SignedRequest: req, SigningKey: signingKey}, nil
}

// buildCanonicalHash returns the hex SHA256 of the request's SigV4 canonical request.
func (req *SignedRequest) buildCanonicalHash() string {
	canonicalSum := sha256.Sum256([]byte(req.CanonicalRequest()))

	return hex.EncodeToString(canonicalSum[:])
}

// CanonicalRequest returns the server-side reconstruction of the client's SigV4 canonical
// request. A signature mismatch means this string differs from the one the client signed, so
// diffing the two is the only way to localise the disagreement; nothing else needs it.
func (req *SignedRequest) CanonicalRequest() string {
	return req.canonicalRequest(false)
}

// RedactedCanonicalRequest renders the canonical request with the session token masked in
// both its header and its presigned query form, for logging a signature mismatch. Everything
// else is retained: signed header values and a payload hash, never the secret key.
func (req *SignedRequest) RedactedCanonicalRequest() string {
	return req.canonicalRequest(true)
}

// canonicalRequest builds the canonical request, masking the session token when redact is set.
// Redaction happens after ordering, so a redacted rendering still lines up with the real one.
func (req *SignedRequest) canonicalRequest(redact bool) string {
	// One (key, value) pair per value; the raw forms drive ordering.
	type queryParam struct{ key, value string }
	params := make([]queryParam, 0, len(req.Canonical.Query))
	for key, values := range req.Canonical.Query {
		for _, value := range values {
			params = append(params, queryParam{key, value})
		}
	}

	slices.SortFunc(params, func(a, b queryParam) int {
		// Key then value as separate fields, never the joined "k=v": '=' outranks the value
		// bytes, so a key that is a prefix of another would sort wrong.
		if a.key != b.key {
			return strings.Compare(a.key, b.key)
		}

		// Order on raw decoded bytes as AWS does (the SDK sorts req.URL.Query() before
		// encoding); encoded order differs once a byte drops below the unreserved range, so
		// "é" sorts after "a" but its "%C3%A9" encoding before it.
		return strings.Compare(a.value, b.value)
	})

	// Encode once, now that ordering is settled.
	pairs := make([]string, len(params))
	for i, p := range params {
		value := httpbinding.EscapePath(p.value, true)
		if redact && strings.EqualFold(p.key, amzSessionName) {
			value = redactedValue
		}

		pairs[i] = httpbinding.EscapePath(p.key, true) + "=" + value
	}

	// SigV4 signs the headers in sorted order, for both the header block and the list below.
	signedHeaders := slices.Sorted(maps.Keys(req.Canonical.SignedHeaders))

	// Canonical headers: "name:value\n" per signed header.
	var headers strings.Builder
	for _, name := range signedHeaders {
		value := req.Canonical.Headers[name]
		if redact && strings.EqualFold(name, amzSessionName) {
			value = redactedValue
		}

		headers.WriteString(name)
		headers.WriteByte(':')
		headers.WriteString(value)
		headers.WriteByte('\n')
	}

	uri := req.Canonical.URI
	if uri == "" {
		uri = "/"
	}

	return strings.Join([]string{
		req.Canonical.Method,
		uri,
		strings.Join(pairs, "&"),
		headers.String(), // trailing '\n' plus the join give the blank line before signed headers
		strings.Join(signedHeaders, ";"),
		req.Canonical.ContentHash,
	}, "\n")
}

// buildStringToSign returns the SigV4 string-to-sign for the given canonical-request hash.
func (req *SignedRequest) buildStringToSign() string {
	// String-to-sign over the credential scope and canonical request hash.
	scope := req.Credential.Date + "/" + req.Credential.Region + "/" + req.Credential.Service + "/" + AmzScopeTerminator

	return strings.Join([]string{
		string(AlgorithmV4),
		req.Timestamp.Format(AmzTimeFormat),
		scope,
		req.buildCanonicalHash(),
	}, "\n")
}

// buildSigningKey derives the dated SigV4 signing key from secretAccessKey.
func (req *SignedRequest) buildSigningKey(secretAccessKey string) []byte {
	// AWS4<secret> -> date -> region -> service -> aws4_request.
	key := hmacSHA256([]byte("AWS4"+secretAccessKey), req.Credential.Date)
	key = hmacSHA256(key, req.Credential.Region)
	key = hmacSHA256(key, req.Credential.Service)
	key = hmacSHA256(key, AmzScopeTerminator)

	return key
}

// hmacSHA256 returns the HMAC-SHA256 of data under key.
func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))

	return mac.Sum(nil)
}
