package auth

import (
	"errors"
	"fmt"
	"strings"
)

// parseIAMARN extracts the account ID and resource name from an IAM ARN of the
// form arn:aws:iam::<accountID>:<resource>/<path>/<name> (path optional). The
// name is the segment after the final "/".
func parseIAMARN(arn, resource string) (accountID, name string, err error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != "aws" || parts[2] != "iam" || parts[3] != "" {
		return "", "", errors.New("not an IAM ARN")
	}
	pathAndName, ok := strings.CutPrefix(parts[5], resource+"/")
	if !ok {
		return "", "", fmt.Errorf("ARN resource is not a %s", resource)
	}
	// LastIndex returning -1 makes the no-path case fall out as the whole string.
	name = pathAndName[strings.LastIndex(pathAndName, "/")+1:]
	if name == "" {
		return "", "", fmt.Errorf("%s name is empty", resource)
	}
	// A real IAM ARN always carries a non-empty account, so an empty account
	// segment is malformed; reject it so callers fail closed.
	if parts[4] == "" {
		return "", "", errors.New("account ID is empty")
	}
	return parts[4], name, nil
}

// ParseRoleARN extracts the account ID and role name from an IAM role ARN of
// the form arn:aws:iam::<accountID>:role/<path>/<name> (path optional). A
// malformed ARN — wrong prefix, non-role resource, empty name, or empty
// account — returns an error; callers that must fail closed treat any error as
// an implicit deny.
func ParseRoleARN(arn string) (accountID, name string, err error) {
	return parseIAMARN(arn, "role")
}

// ErrInvalidRoleARN reports a role ARN that does not parse. ErrRoleARNMismatch
// reports one that parses but is not the ARN the store holds for the role it
// names, which callers must treat as an implicit deny.
var (
	ErrInvalidRoleARN  = errors.New("malformed role ARN")
	ErrRoleARNMismatch = errors.New("role ARN is not the stored ARN for that role")
)

// RoleARNLookup returns the canonical ARN the store holds for a role, or an
// error if it cannot be read.
type RoleARNLookup func(accountID, roleName string) (storedARN string, err error)

// ResolveRoleARN resolves the role a caller-supplied ARN names and verifies the
// ARN is the one the store holds. ParseRoleARN discards any path, so comparing
// the stored ARN back is what stops an invented path reaching a role the ARN
// does not name. An error from lookup is returned unwrapped.
func ResolveRoleARN(roleARN string, lookup RoleARNLookup) (accountID, roleName string, err error) {
	accountID, roleName, err = ParseRoleARN(roleARN)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrInvalidRoleARN, err)
	}
	storedARN, err := lookup(accountID, roleName)
	if err != nil {
		return "", "", err
	}
	if storedARN != roleARN {
		return "", "", ErrRoleARNMismatch
	}
	return accountID, roleName, nil
}

// ParsePolicyARN extracts the account ID and policy name from an IAM policy ARN
// of the form arn:aws:iam::<accountID>:policy/<path>/<name> (path optional). It
// fails closed on a malformed ARN exactly as ParseRoleARN does. An AWS-managed
// ARN parses with accountID "aws"; use IsAWSManagedPolicyARN to distinguish it.
func ParsePolicyARN(arn string) (accountID, name string, err error) {
	return parseIAMARN(arn, "policy")
}

// ParseInstanceProfileARN extracts the account ID and profile name from an IAM
// instance-profile ARN of the form
// arn:aws:iam::<accountID>:instance-profile/<path>/<name> (path optional). It
// fails closed on a malformed ARN exactly as ParseRoleARN does.
func ParseInstanceProfileARN(arn string) (accountID, name string, err error) {
	return parseIAMARN(arn, "instance-profile")
}

// IsAWSManagedPolicyARN reports whether arn is a structurally valid AWS-managed
// policy ARN. Such policies use the literal account "aws" and have no backing
// document in an account's policy store.
func IsAWSManagedPolicyARN(arn string) bool {
	accountID, _, err := ParsePolicyARN(arn)
	return err == nil && accountID == "aws"
}
