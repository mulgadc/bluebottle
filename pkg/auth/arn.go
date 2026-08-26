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
	prefix := resource + "/"
	if !strings.HasPrefix(parts[5], prefix) {
		return "", "", fmt.Errorf("ARN resource is not a %s", resource)
	}
	pathAndName := parts[5][len(prefix):]
	if slash := strings.LastIndex(pathAndName, "/"); slash >= 0 {
		name = pathAndName[slash+1:]
	} else {
		name = pathAndName
	}
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

// ParsePolicyARN extracts the account ID and policy name from an IAM policy ARN
// of the form arn:aws:iam::<accountID>:policy/<path>/<name> (path optional). It
// fails closed on a malformed ARN exactly as ParseRoleARN does. An AWS-managed
// ARN parses with accountID "aws"; use IsAWSManagedPolicyARN to distinguish it.
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
