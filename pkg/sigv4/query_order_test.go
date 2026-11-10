package sigv4_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/mulgadc/bluebottle/pkg/sigv4"
)

// SigV4 sorts the canonical query after encoding. These keys and values sort one way raw and
// the other way encoded ('/' > '-', but '%' < '-'), so a raw-order verifier rejects them.
func TestCanonicalQuery_SortsAfterEncoding(t *testing.T) {
	const wantQuery = "a%2Fb=1&a-b=1&k=a%2Fb&k=a-b"

	tests := []struct {
		name      string
		presigned bool
	}{
		{name: "header"},
		{name: "presigned", presigned: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://"+oracleHost+"/key?k=a-b&a-b=1&k=a/b&a/b=1", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}

			creds := aws.Credentials{AccessKeyID: oracleAKID, SecretAccessKey: oracleSecret}
			payload := string(sigv4.UnsignedPayload)
			signer := v4.NewSigner()
			if tc.presigned {
				q := req.URL.Query()
				q.Set("X-Amz-Expires", "300")
				req.URL.RawQuery = q.Encode()

				uri, _, err := signer.PresignHTTP(context.Background(), creds, req, payload, "s3", "us-east-1", oracleTime, s3Opts("s3")...)
				if err != nil {
					t.Fatalf("PresignHTTP: %v", err)
				}

				if req, err = http.NewRequest(http.MethodGet, uri, nil); err != nil {
					t.Fatalf("rebuild presigned request: %v", err)
				}
			} else {
				req.Header.Set("X-Amz-Content-Sha256", payload)
				if err := signer.SignHTTP(context.Background(), creds, req, payload, "s3", "us-east-1", oracleTime, s3Opts("s3")...); err != nil {
					t.Fatalf("SignHTTP: %v", err)
				}
			}

			signed, err := sigv4.Parse(req, sigv4.WithTime(oracleTime))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			if _, err := signed.Verify(oracleSecret, "us-east-1", "s3"); err != nil {
				t.Fatalf("SDK-signed request rejected: %v\ncanonical request:\n%s", err, signed.CanonicalRequest())
			}

			// The presigned form carries X-Amz-* parameters too; uppercase sorts first, so ours end it.
			query := strings.Split(signed.CanonicalRequest(), "\n")[2]
			if !strings.HasSuffix(query, wantQuery) {
				t.Errorf("canonical query = %q, want suffix %q", query, wantQuery)
			}
		})
	}
}
