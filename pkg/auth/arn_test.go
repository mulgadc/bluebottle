package auth_test

import (
	"testing"

	"github.com/mulgadc/bluebottle/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRoleARN(t *testing.T) {
	tests := []struct {
		name        string
		arn         string
		wantAccount string
		wantName    string
		wantErr     bool
	}{
		{"simple", "arn:aws:iam::000000000001:role/MyRole", "000000000001", "MyRole", false},
		{"nested path", "arn:aws:iam::000000000001:role/some/path/MyRole", "000000000001", "MyRole", false},
		{"role prefix only", "arn:aws:iam::000000000001:role/", "", "", true},
		{"trailing slash, empty name", "arn:aws:iam::000000000001:role/path/", "", "", true},
		{"empty account", "arn:aws:iam:::role/MyRole", "", "", true},
		{"not a role resource", "arn:aws:iam::000000000001:user/Bob", "", "", true},
		{"region present", "arn:aws:iam:us-east-1:000000000000:role/app", "", "", true},
		{"wrong service", "arn:aws:s3:::000000000001:role/MyRole", "", "", true},
		{"too few fields", "arn:aws:iam::000000000001", "", "", true},
		{"junk", "not-an-arn", "", "", true},
		{"empty", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account, name, err := auth.ParseRoleARN(tt.arn)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, account, "account must be empty on error")
				assert.Empty(t, name, "name must be empty on error")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAccount, account, "account")
			assert.Equal(t, tt.wantName, name, "name")
		})
	}
}

func TestParsePolicyARN(t *testing.T) {
	tests := []struct {
		name        string
		arn         string
		wantAccount string
		wantName    string
		wantErr     bool
	}{
		{"simple", "arn:aws:iam::000000000001:policy/AdministratorAccess", "000000000001", "AdministratorAccess", false},
		{"nested path", "arn:aws:iam::000000000001:policy/path/to/MyPolicy", "000000000001", "MyPolicy", false},
		// Parses cleanly; rejecting a foreign account is the caller's job.
		{"foreign account", "arn:aws:iam::999999999999:policy/AdministratorAccess", "999999999999", "AdministratorAccess", false},
		{"aws managed", "arn:aws:iam::aws:policy/AdministratorAccess", "aws", "AdministratorAccess", false},
		{"policy-backup near miss", "arn:aws:iam::000000000001:policy-backup/Foo", "", "", true},
		{"policyset near miss", "arn:aws:iam::000000000001:policyset/Foo", "", "", true},
		{"policy prefix only", "arn:aws:iam::000000000001:policy/", "", "", true},
		{"trailing slash, empty name", "arn:aws:iam::000000000001:policy/path/", "", "", true},
		{"not a policy resource", "arn:aws:iam::000000000001:role/Foo", "", "", true},
		{"region present", "arn:aws:iam:us-east-1:000000000001:policy/Foo", "", "", true},
		{"empty account", "arn:aws:iam:::policy/Foo", "", "", true},
		{"wrong partition", "arn:partition:iam::000000000001:policy/Foo", "", "", true},
		{"wrong service", "arn:aws:s3::000000000001:policy/Foo", "", "", true},
		{"too few fields", "arn:aws:iam::000000000001", "", "", true},
		{"junk", "invalid-arn", "", "", true},
		{"empty", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			account, name, err := auth.ParsePolicyARN(tt.arn)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, account, "account must be empty on error")
				assert.Empty(t, name, "name must be empty on error")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAccount, account, "account")
			assert.Equal(t, tt.wantName, name, "name")
		})
	}
}

func TestIsAWSManagedPolicyARN(t *testing.T) {
	tests := []struct {
		arn  string
		want bool
	}{
		{"arn:aws:iam::aws:policy/AdministratorAccess", true},
		{"arn:aws:iam::aws:policy/service-role/AmazonEKSWorkerNodePolicy", true},
		{"arn:aws:iam::aws:policy/", false},
		{"arn:aws:iam::aws:policy/service-role/", false},
		{"arn:aws:iam::000000000001:policy/AdministratorAccess", false},
		{"arn:aws:iam::aws:policy-backup/AdministratorAccess", false},
		{"arn:aws:iam::awsx:policy/AdministratorAccess", false},
		{"", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, auth.IsAWSManagedPolicyARN(tt.arn), "IsAWSManagedPolicyARN(%q)", tt.arn)
	}
}
