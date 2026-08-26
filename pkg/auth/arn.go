package auth

import (
	"errors"
	"strings"
)

// ParseRoleARN extracts the account ID and role name from an IAM role ARN of
// the form arn:aws:iam::<accountID>:role/<path>/<name> (path optional). The
// name is the segment after the final "/". A malformed ARN — wrong prefix,
// non-role resource, empty name, or empty account — returns an error; callers
// that must fail closed treat any error as an implicit deny.
func ParseRoleARN(arn string) (accountID, name string, err error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != "aws" || parts[2] != "iam" || parts[3] != "" {
		return "", "", errors.New("not an IAM ARN")
	}
	const prefix = "role/"
	resource := parts[5]
	if !strings.HasPrefix(resource, prefix) {
		return "", "", errors.New("ARN resource is not a role")
	}
	pathAndName := resource[len(prefix):]
	if slash := strings.LastIndex(pathAndName, "/"); slash >= 0 {
		name = pathAndName[slash+1:]
	} else {
		name = pathAndName
	}
	if name == "" {
		return "", "", errors.New("role name is empty")
	}
	// A real IAM role ARN always carries a non-empty account, so an empty
	// account segment is malformed; reject it so callers fail closed.
	if parts[4] == "" {
		return "", "", errors.New("account ID is empty")
	}
	return parts[4], name, nil
}

// AWSManagedPolicyARNPrefix is the prefix of an AWS-managed policy ARN, whose
// account segment is the literal "aws" rather than a numeric account ID.
const AWSManagedPolicyARNPrefix = "arn:aws:iam::aws:policy/"

// ParsePolicyARN extracts the account ID and policy name from an IAM policy ARN
// of the form arn:aws:iam::<accountID>:policy/<path>/<name> (path optional). The
// name is the segment after the final "/". A malformed ARN — wrong prefix,
// non-policy resource, empty name, or empty account — returns an error; callers
// that must fail closed treat any error as an implicit deny. An AWS-managed ARN
// parses with accountID "aws"; use IsAWSManagedPolicyARN to distinguish it.
func ParsePolicyARN(arn string) (accountID, name string, err error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != "aws" || parts[2] != "iam" || parts[3] != "" {
		return "", "", errors.New("not an IAM ARN")
	}
	const prefix = "policy/"
	resource := parts[5]
	if !strings.HasPrefix(resource, prefix) {
		return "", "", errors.New("ARN resource is not a policy")
	}
	pathAndName := resource[len(prefix):]
	if slash := strings.LastIndex(pathAndName, "/"); slash >= 0 {
		name = pathAndName[slash+1:]
	} else {
		name = pathAndName
	}
	if name == "" {
		return "", "", errors.New("policy name is empty")
	}
	if parts[4] == "" {
		return "", "", errors.New("account ID is empty")
	}
	return parts[4], name, nil
}

// IsAWSManagedPolicyARN reports whether arn names an AWS-managed policy, which
// has no backing document in this stack and is resolved from a builtin registry
// (or to no grant at all) rather than from an account's policy store.
func IsAWSManagedPolicyARN(arn string) bool {
	return strings.HasPrefix(arn, AWSManagedPolicyARNPrefix)
}
