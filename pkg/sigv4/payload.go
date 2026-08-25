package sigv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

// payloadMode classifies an S3 x-amz-content-sha256 value as a recognised sentinel, or as a
// literal payload digest (the empty mode). An unrecognised value is rejected rather than
// signed verbatim, which would let a client opt its body out of the signature.
func payloadMode(contentHash string) (ContentMode, error) {
	switch mode := ContentMode(contentHash); mode {
	case UnsignedPayload, StreamingSigned, StreamingSignedTrailer, StreamingUnsignedTrailer:
		return mode, nil
	}

	if len(contentHash) == hex.EncodedLen(sha256.Size) {
		if _, err := hex.DecodeString(contentHash); err == nil {
			return "", nil
		}
	}

	return "", fmt.Errorf("%w: %q", ErrInvalidContentSHA256, contentHash)
}

// bindPayload binds the request body to the digest signed in x-amz-content-sha256, so the
// signature covers the bytes on the wire and not just the declared hash. It runs after the
// signature check, keeping the body read off the unauthenticated path.
func (req *SignedRequest) bindPayload() error {
	// A sentinel leaves the body outside the signature, and a non-S3 request already hashed
	// its body into the canonical request during Parse.
	if req.Canonical.PayloadMode != "" || req.Credential.Service != "s3" || req.req == nil {
		return nil
	}

	digest := strings.ToLower(req.Canonical.ContentHash)

	body := req.req.Body
	if body == nil || body == http.NoBody {
		if digest != EmptyPayload {
			return fmt.Errorf("%w: request has no body", ErrContentSHA256Mismatch)
		}

		return nil
	}

	// A body of known, modest size verifies here, so a tampered payload fails authentication
	// outright. Anything larger or of unknown length streams instead of being buffered.
	if length := req.req.ContentLength; length >= 0 && length <= MaxPayloadLen {
		buf, err := io.ReadAll(io.LimitReader(body, length))
		if err != nil {
			return fmt.Errorf("reading request body to verify payload hash: %w", err)
		}

		// Rewind the consumed body so the handler can still read it.
		_ = body.Close()
		req.req.Body = io.NopCloser(bytes.NewReader(buf))

		sum := sha256.Sum256(buf)
		if hex.EncodeToString(sum[:]) != digest {
			return ErrContentSHA256Mismatch
		}

		return nil
	}

	req.req.Body = &verifiedBody{body: body, digest: digest, hash: sha256.New()}

	return nil
}

// verifiedBody hashes a request body as its consumer reads it and fails the read that reaches
// EOF unless the body matches the signed digest. Verification can only complete at the end of
// the stream, so a consumer that stops early has not verified anything.
type verifiedBody struct {
	body   io.ReadCloser
	hash   hash.Hash
	digest string
	err    error
}

func (b *verifiedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}

	n, err := b.body.Read(p)
	if n > 0 {
		b.hash.Write(p[:n])
	}

	if errors.Is(err, io.EOF) && hex.EncodeToString(b.hash.Sum(nil)) != b.digest {
		// Sticky, so a consumer that keeps reading cannot read past the failure into a
		// clean EOF and treat the body as complete.
		b.err = ErrContentSHA256Mismatch

		return n, b.err
	}

	return n, err
}

func (b *verifiedBody) Close() error { return b.body.Close() }
