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

// ErrInvalidPolicyARN and ErrPolicyARNMismatch are ResolvePolicyARN's
// counterparts to ErrInvalidRoleARN and ErrRoleARNMismatch.
var (
	ErrInvalidPolicyARN  = errors.New("malformed policy ARN")
	ErrPolicyARNMismatch = errors.New("policy ARN is not the stored ARN for that policy")
)

// ErrInvalidInstanceProfileARN and ErrInstanceProfileARNMismatch are
// ResolveInstanceProfileARN's counterparts to ErrInvalidRoleARN and ErrRoleARNMismatch.
var (
	ErrInvalidInstanceProfileARN  = errors.New("malformed instance profile ARN")
	ErrInstanceProfileARNMismatch = errors.New("instance profile ARN is not the stored ARN for that instance profile")
)

// ARNLookup returns the canonical ARN the store holds for the named IAM
// resource, or an error if it cannot be read.
type ARNLookup func(accountID, name string) (storedARN string, err error)

// RoleARNLookup returns the canonical ARN the store holds for a role.
type RoleARNLookup = ARNLookup

// resolveIAMARN parses a caller-supplied ARN, looks up the stored ARN for the
// name it carries and requires the two to be identical. Parsing discards any
// path, so the comparison is what rejects a non-canonical spelling.
func resolveIAMARN(arn, resource string, lookup ARNLookup, errInvalid, errMismatch error) (accountID, name string, err error) {
	accountID, name, err = parseIAMARN(arn, resource)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", errInvalid, err)
	}
	storedARN, err := lookup(accountID, name)
	if err != nil {
		return "", "", err
	}
	if storedARN != arn {
		return "", "", errMismatch
	}
	return accountID, name, nil
}

// ResolveRoleARN resolves the role a caller-supplied ARN names and verifies the
// ARN is the one the store holds. ParseRoleARN discards any path, so comparing
// the stored ARN back is what stops an invented path reaching a role the ARN
// does not name. An error from lookup is returned unwrapped.
func ResolveRoleARN(roleARN string, lookup RoleARNLookup) (accountID, roleName string, err error) {
	return resolveIAMARN(roleARN, "role", lookup, ErrInvalidRoleARN, ErrRoleARNMismatch)
}

// ResolvePolicyARN is ResolveRoleARN for a customer-managed policy ARN. An
// AWS-managed ARN has no stored record, so callers screen it out with
// IsAWSManagedPolicyARN before resolving.
func ResolvePolicyARN(policyARN string, lookup ARNLookup) (accountID, policyName string, err error) {
	return resolveIAMARN(policyARN, "policy", lookup, ErrInvalidPolicyARN, ErrPolicyARNMismatch)
}

// ResolveInstanceProfileARN is ResolveRoleARN for an instance-profile ARN.
func ResolveInstanceProfileARN(profileARN string, lookup ARNLookup) (accountID, profileName string, err error) {
	return resolveIAMARN(profileARN, "instance-profile", lookup, ErrInvalidInstanceProfileARN, ErrInstanceProfileARNMismatch)
}

// ParsePolicyARN extracts the account ID and name from arn:aws:iam::<account>:policy/<path>/<name>,
// failing closed like ParseRoleARN; an AWS-managed ARN has accountID "aws". It
// discards the path, so resolve a caller-supplied ARN with ResolvePolicyARN.
func ParsePolicyARN(arn string) (accountID, name string, err error) {
	return parseIAMARN(arn, "policy")
}

// IsAWSManagedPolicyARN reports whether arn is a structurally valid AWS-managed
// policy ARN. Such policies use the literal account "aws" and have no backing
// document in an account's policy store.
func IsAWSManagedPolicyARN(arn string) bool {
	accountID, _, err := ParsePolicyARN(arn)
	return err == nil && accountID == "aws"
}
