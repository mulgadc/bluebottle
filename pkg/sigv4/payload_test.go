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

// largeSignedBody signs a body over MaxPayloadLen under digest, runs the signature check, and
// returns the streaming body a handler would be given. wrap replaces what the wrapper reads
// from, so a test can choose how the transport frames its reads.
func largeSignedBody(tb testing.TB, sent []byte, digest string, wrap func([]byte) io.ReadCloser) io.ReadCloser {
	tb.Helper()

	req := signS3(tb, sent, digest)
	if wrap != nil {
		req.Body = wrap(sent)
	}

	signed, err := sigv4.Parse(req, sigv4.WithTime(oracleTime))
	if err != nil {
		tb.Fatalf("Parse: %v", err)
	}

	if _, err := signed.Verify(oracleSecret, "us-east-1", "s3"); err != nil {
		tb.Fatalf("Verify: %v", err)
	}

	return req.Body
}

// eofWithData returns the last of its bytes and io.EOF from the same Read. io.ReadAtLeast is
// free to discard an error paired with a full byte count, so a wrapper that reports the
// mismatch that way alone reports it to nobody.
type eofWithData struct{ b []byte }

func (r *eofWithData) Read(p []byte) (int, error) {
	n := copy(p, r.b)
	r.b = r.b[n:]

	if len(r.b) == 0 {
		return n, io.EOF
	}

	return n, nil
}

func (r *eofWithData) Close() error { return nil }

// truncatedBody returns half its bytes and then io.ErrUnexpectedEOF, which is what net/http
// gives a reader when a body ends before its declared Content-Length.
type truncatedBody struct{ b []byte }

func (r *truncatedBody) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.ErrUnexpectedEOF
	}

	n := copy(p, r.b[:len(r.b)/2+1])
	r.b = r.b[n:]

	return n, nil
}

func (r *truncatedBody) Close() error { return nil }

// TestVerifyLargePayloadRejectsTruncatedBody covers a streamed body that ends before its
// declared length. It can no more hash to the signed digest than a rewritten one can, so it
// has to fail as a mismatch rather than as the read error that would answer 500.
func TestVerifyLargePayloadRejectsTruncatedBody(t *testing.T) {
	body := bytes.Repeat([]byte("a"), sigv4.MaxPayloadLen+1)

	rc := largeSignedBody(t, body, sha256Hex(body), func(b []byte) io.ReadCloser {
		return &truncatedBody{b: b}
	})

	if _, err := io.ReadAll(rc); !errors.Is(err, sigv4.ErrContentSHA256Mismatch) {
		t.Fatalf("read truncated body: got %v, want %v", err, sigv4.ErrContentSHA256Mismatch)
	}
}

// TestVerifyLargePayloadFailsConsumersThatStopAtContentLength covers the read idioms that take
// the declared length as the end of the body and never issue the read that returns EOF. Each
// one has a contract that drops an error arriving with a full byte count, so the mismatch has
// to reach them as a short read.
func TestVerifyLargePayloadFailsConsumersThatStopAtContentLength(t *testing.T) {
	body := bytes.Repeat([]byte("a"), sigv4.MaxPayloadLen+1)
	rewritten := bytes.Repeat([]byte("b"), len(body))

	tests := []struct {
		name string
		wrap func([]byte) io.ReadCloser
		read func(io.Reader, []byte) (int, error)
	}{
		{
			name: "io.ReadFull",
			read: func(r io.Reader, buf []byte) (int, error) { return io.ReadFull(r, buf) },
		},
		{
			name: "io.ReadAtLeast over a body that ends with (n, io.EOF)",
			wrap: func(b []byte) io.ReadCloser { return &eofWithData{b: b} },
			read: func(r io.Reader, buf []byte) (int, error) { return io.ReadAtLeast(r, buf, len(buf)) },
		},
		{
			name: "io.CopyN",
			read: func(r io.Reader, buf []byte) (int, error) {
				n, err := io.CopyN(io.Discard, r, int64(len(buf)))

				return int(n), err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("rewritten", func(t *testing.T) {
				rc := largeSignedBody(t, rewritten, sha256Hex(body), tc.wrap)

				if _, err := tc.read(rc, make([]byte, len(body))); !errors.Is(err, sigv4.ErrContentSHA256Mismatch) {
					t.Fatalf("read rewritten body: got %v, want %v", err, sigv4.ErrContentSHA256Mismatch)
				}
			})

			t.Run("intact", func(t *testing.T) {
				rc := largeSignedBody(t, body, sha256Hex(body), tc.wrap)

				n, err := tc.read(rc, make([]byte, len(body)))
				if err != nil {
					t.Fatalf("read intact body: %v", err)
				}
				if n != len(body) {
					t.Fatalf("read %d bytes, want %d", n, len(body))
				}
			})
		})
	}
}
