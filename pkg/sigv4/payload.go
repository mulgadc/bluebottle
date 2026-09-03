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
		// ContentLength is the exact size, so the buffer is allocated once. io.ReadAll would
		// grow by repeated doubling instead, allocating about twice the body.
		buf := make([]byte, length)
		if _, err := io.ReadFull(body, buf); err != nil {
			// A body shorter than its declared length cannot hash to the signed digest, so
			// it fails the same way a rewritten one does rather than as a read error.
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return ErrContentSHA256Mismatch
			}

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

	req.req.Body = &verifiedBody{
		body:      body,
		digest:    digest,
		hash:      sha256.New(),
		remaining: req.req.ContentLength,
		sized:     req.req.ContentLength >= 0,
	}

	return nil
}

// verifiedBody hashes a request body as its consumer reads it and fails the read that
// completes the body unless it matches the signed digest. The declared length ends the body
// as surely as EOF does, so a consumer that never reads past the last byte is still covered;
// one that stops before it has verified nothing, which Close reports.
type verifiedBody struct {
	body      io.ReadCloser
	hash      hash.Hash
	digest    string
	remaining int64 // declared bytes still to come, meaningful only when sized
	sized     bool
	verified  bool
	err       error
}

func (b *verifiedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}

	n, err := b.body.Read(p)
	if n > 0 {
		b.hash.Write(p[:n])
		b.remaining -= int64(n)
	}

	if !b.verified && (b.sized && b.remaining <= 0 || errors.Is(err, io.EOF)) {
		if hex.EncodeToString(b.hash.Sum(nil)) != b.digest {
			// Sticky, so a consumer that keeps reading cannot read past the failure into a
			// clean EOF and treat the body as complete. The bytes from this read are withheld
			// as well: io.ReadFull, io.ReadAtLeast and io.CopyN all discard an error that
			// arrives alongside a full byte count, so a short read is what reaches them.
			b.err = ErrContentSHA256Mismatch

			return 0, b.err
		}

		b.verified = true
	}

	return n, err
}

// Close reports a body that was abandoned before the digest could be compared, so leaving the
// stream unread cannot pass for verifying it. The underlying body is closed either way.
func (b *verifiedBody) Close() error {
	err := b.body.Close()

	switch {
	case b.err != nil:
		return b.err
	case !b.verified:
		return fmt.Errorf("%w: body closed before it was verified", ErrContentSHA256Mismatch)
	}

	return err
}
