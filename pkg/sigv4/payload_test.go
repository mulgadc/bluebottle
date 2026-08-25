package sigv4_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/mulgadc/bluebottle/pkg/sigv4"
)

// signS3 signs a PUT of body against the oracle credentials, sending payloadHash as
// x-amz-content-sha256. A caller passes a sentinel, or a digest that need not match body.
func signS3(tb testing.TB, body []byte, payloadHash string) *http.Request {
	tb.Helper()

	req, err := http.NewRequest(http.MethodPut, "https://"+oracleHost+"/object.txt", bytes.NewReader(body))
	if err != nil {
		tb.Fatalf("build request: %v", err)
	}

	req.ContentLength = int64(len(body))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	creds := aws.Credentials{AccessKeyID: oracleAKID, SecretAccessKey: oracleSecret}
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req, payloadHash, "s3", "us-east-1", oracleTime, s3Opts("s3")...); err != nil {
		tb.Fatalf("SignHTTP: %v", err)
	}

	return req
}

// sha256Hex returns the hex SHA-256 of b, the x-amz-content-sha256 value a client sends.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// TestVerifyBindsBodyToContentSHA256 covers the S3 payload-binding decision for each
// x-amz-content-sha256 form: a digest binds the body, a recognised sentinel does not, and an
// unrecognised value is rejected outright.
func TestVerifyBindsBodyToContentSHA256(t *testing.T) {
	body := []byte("hello")

	tests := []struct {
		name        string
		body        []byte
		payloadHash string
		want        error
	}{
		{name: "matching digest", body: body, payloadHash: sha256Hex(body)},
		{name: "empty body", payloadHash: sigv4.EmptyPayload},
		{name: "rewritten body", body: []byte("goodbye"), payloadHash: sha256Hex(body), want: sigv4.ErrContentSHA256Mismatch},
		{name: "truncated body", body: body[:2], payloadHash: sha256Hex(body), want: sigv4.ErrContentSHA256Mismatch},
		{name: "body under an empty-payload digest", body: body, payloadHash: sigv4.EmptyPayload, want: sigv4.ErrContentSHA256Mismatch},
		{name: "unsigned payload", body: body, payloadHash: string(sigv4.UnsignedPayload)},
		{name: "streaming seed", body: body, payloadHash: string(sigv4.StreamingSigned)},
		{name: "streaming trailer seed", body: body, payloadHash: string(sigv4.StreamingUnsignedTrailer)},
		{name: "invented sentinel", body: body, payloadHash: "UNSIGNED", want: sigv4.ErrInvalidContentSHA256},
		{name: "short digest", body: body, payloadHash: sha256Hex(body)[:63], want: sigv4.ErrInvalidContentSHA256},
		{name: "non-hex digest", body: body, payloadHash: "z" + sha256Hex(body)[1:], want: sigv4.ErrInvalidContentSHA256},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The signature covers the declared hash, so signing tc.body with tc.payloadHash
			// reproduces exactly the on-path rewrite: a valid signature over other bytes.
			req := signS3(t, tc.body, tc.payloadHash)

			err := parseVerify(req, "us-east-1", "s3", oracleTime)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifyStreamsLargePayload checks that a body too large to buffer is verified as the
// caller reads it rather than at Verify, and that the read fails when it has been rewritten.
func TestVerifyStreamsLargePayload(t *testing.T) {
	body := bytes.Repeat([]byte("a"), sigv4.MaxPayloadLen+1)

	for _, tamper := range []bool{false, true} {
		name := "intact"
		if tamper {
			name = "rewritten"
		}

		t.Run(name, func(t *testing.T) {
			digest := sha256Hex(body)
			sent := body
			if tamper {
				sent = bytes.Repeat([]byte("b"), len(body))
			}

			req := signS3(t, sent, digest)

			signed, err := sigv4.Parse(req, sigv4.WithTime(oracleTime))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			// Verify cannot decide either way: the body is only hashed as it is consumed.
			if _, err := signed.Verify(oracleSecret, "us-east-1", "s3"); err != nil {
				t.Fatalf("Verify: %v", err)
			}

			got, err := io.ReadAll(req.Body)
			if !tamper {
				if err != nil {
					t.Fatalf("read verified body: %v", err)
				}
				if !bytes.Equal(got, body) {
					t.Fatalf("body: got %d bytes, want %d", len(got), len(body))
				}

				return
			}

			if !errors.Is(err, sigv4.ErrContentSHA256Mismatch) {
				t.Fatalf("read rewritten body: got %v, want %v", err, sigv4.ErrContentSHA256Mismatch)
			}
		})
	}
}
