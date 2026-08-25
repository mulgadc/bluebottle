package sigv4_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/mulgadc/bluebottle/pkg/sigv4"
)

// benchSizes straddle MaxPayloadLen (10 MiB): the first three take the branch that buffers
// the whole body, the last streams it through verifiedBody.
var benchSizes = []struct {
	name string
	size int
}{
	{name: "64KiB", size: 64 << 10},
	{name: "1MiB", size: 1 << 20},
	{name: "8MiB", size: 8 << 20},
	{name: "32MiB", size: 32 << 20},
}

// BenchmarkVerifyPayload measures the cost the payload binding adds to a signed PUT. The
// digest cases hash the body; UNSIGNED-PAYLOAD is the same request with the binding skipped,
// so the pair isolates the hashing from the rest of Parse and Verify.
func BenchmarkVerifyPayload(b *testing.B) {
	for _, sz := range benchSizes {
		body := bytes.Repeat([]byte("x"), sz.size)

		modes := []struct {
			name        string
			payloadHash string
		}{
			{name: "digest", payloadHash: sha256Hex(body)},
			{name: "unsigned", payloadHash: string(sigv4.UnsignedPayload)},
		}

		for _, mode := range modes {
			b.Run(sz.name+"/"+mode.name, func(b *testing.B) {
				// Signing once keeps the SDK signer out of the measurement: the signature
				// covers the declared hash, not the bytes, so it stays valid for every
				// iteration that replays the same body.
				signed := signS3(b, body, mode.payloadHash)

				b.SetBytes(int64(sz.size))
				b.ReportAllocs()
				b.ResetTimer()

				for range b.N {
					req := replayRequest(signed, body)

					parsed, err := sigv4.Parse(req, sigv4.WithTime(oracleTime))
					if err != nil {
						b.Fatalf("parse: %v", err)
					}

					if _, err := parsed.Verify(oracleSecret, "us-east-1", "s3"); err != nil {
						b.Fatalf("verify: %v", err)
					}

					// A streamed body is only compared at EOF, so the drain is part of the
					// cost of verifying it. It is what the gate does after the write.
					if _, err := io.Copy(io.Discard, req.Body); err != nil {
						b.Fatalf("drain: %v", err)
					}
				}
			})
		}
	}
}

// replayRequest rebuilds a signed request against a fresh reader over the same body, so each
// iteration starts from an unconsumed stream without re-signing.
func replayRequest(signed *http.Request, body []byte) *http.Request {
	req := signed.Clone(signed.Context())
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))

	return req
}
