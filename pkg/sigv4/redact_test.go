package sigv4_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/mulgadc/bluebottle/pkg/sigv4"
)

const oracleToken = "SUPERSECRETSESSIONTOKEN"

// The session token reaches the log on a signature mismatch, so it must be masked in both the
// header form and the presigned query form.
func TestRedactedCanonicalRequest_MasksSessionToken(t *testing.T) {
	tests := []struct {
		name      string
		presigned bool
		want      string
	}{
		{name: "header", want: "x-amz-security-token:<redacted>"},
		{name: "presigned", presigned: true, want: "X-Amz-Security-Token=<redacted>"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := sigv4.Parse(signWithToken(t, tc.presigned), sigv4.WithTime(oracleTime))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			out := signed.RedactedCanonicalRequest()
			if strings.Contains(out, oracleToken) {
				t.Errorf("session token reached the redacted canonical request:\n%s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("missing %q in:\n%s", tc.want, out)
			}

			// The unredacted form still carries it: only the logging path is masked.
			if !strings.Contains(signed.CanonicalRequest(), oracleToken) {
				t.Error("CanonicalRequest must keep the token; it is signed")
			}
		})
	}
}

// signWithToken returns a request signed with a session token, header or presigned.
func signWithToken(t *testing.T, presigned bool) *http.Request {
	t.Helper()

	creds := aws.Credentials{AccessKeyID: oracleAKID, SecretAccessKey: oracleSecret, SessionToken: oracleToken}
	req, err := http.NewRequest(http.MethodGet, "https://"+oracleHost+"/key", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	if presigned {
		q := req.URL.Query()
		q.Set("X-Amz-Expires", strconv.Itoa(900))
		req.URL.RawQuery = q.Encode()

		signedURI, _, err := v4.NewSigner().PresignHTTP(context.Background(), creds, req,
			string(sigv4.UnsignedPayload), "s3", "us-east-1", oracleTime, s3Opts("s3")...)
		if err != nil {
			t.Fatalf("PresignHTTP: %v", err)
		}

		out, err := http.NewRequest(http.MethodGet, signedURI, nil)
		if err != nil {
			t.Fatalf("rebuild presigned request: %v", err)
		}

		return out
	}

	req.Header.Set("X-Amz-Content-Sha256", string(sigv4.UnsignedPayload))
	if err := v4.NewSigner().SignHTTP(context.Background(), creds, req,
		string(sigv4.UnsignedPayload), "s3", "us-east-1", oracleTime, s3Opts("s3")...); err != nil {
		t.Fatalf("SignHTTP: %v", err)
	}

	return req
}
