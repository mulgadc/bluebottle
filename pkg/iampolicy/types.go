// Package iampolicy holds the canonical IAM policy-document DTOs and the
// explicit-deny-wins access evaluator shared by predastore and spinifex. It is a
// leaf package (stdlib-only) so both modules can depend on it without a cycle.
package iampolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

const (
	// EffectAllow is the statement Effect that grants access.
	EffectAllow = "Allow"
	// EffectDeny is the statement Effect that denies access (wins over Allow).
	EffectDeny = "Deny"
)

// PolicyDocument is the parsed IAM policy JSON structure.
type PolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement is a single statement within a policy document. NotAction,
// NotResource and Principal are modelled so they are enforced rather than
// dropped at parse; Principal has no meaning on an identity policy and exists
// only so the write path can reject it.
type Statement struct {
	Sid       string                               `json:"Sid,omitempty"`
	Effect    string                               `json:"Effect"`
	Action    StringOrArr                          `json:"Action"`
	Resource  StringOrArr                          `json:"Resource"`
	Condition map[string]map[string]ConditionValue `json:"Condition,omitempty"`

	NotAction   StringOrArr     `json:"NotAction,omitempty"`
	NotResource StringOrArr     `json:"NotResource,omitempty"`
	Principal   json.RawMessage `json:"Principal,omitempty"`
}

// ConditionValue is the leaf of a Condition block. AWS emits strings, arrays,
// bools and numbers here, so scalars are coerced to their string form rather
// than rejected — comparison semantics are textual either way.
type ConditionValue []string

// UnmarshalJSON accepts a string, an array of strings, a bool, a number or
// null. Anything else is an error, but the accepted set covers every shape AWS
// produces, so a valid document never fails to load.
func (c *ConditionValue) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	if arr, ok := raw.([]any); ok {
		out := make([]string, 0, len(arr))
		for _, elem := range arr {
			s, err := conditionScalar(elem)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		*c = out
		return nil
	}
	if raw == nil {
		*c = nil
		return nil
	}
	s, err := conditionScalar(raw)
	if err != nil {
		return err
	}
	*c = []string{s}
	return nil
}

// MarshalJSON emits the string form: a bare string for one value, otherwise an
// array. Byte-exact round-tripping is not preserved (true becomes "true"), which
// is safe because callers serve the stored document, not the re-marshalled one.
func (c ConditionValue) MarshalJSON() ([]byte, error) {
	if len(c) == 1 {
		return json.Marshal(c[0])
	}
	return json.Marshal([]string(c))
}

// conditionScalar coerces one decoded JSON scalar to its string form. Numbers
// keep their literal text, so 10 stays "10" rather than becoming "1e+01".
func conditionScalar(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case json.Number:
		return t.String(), nil
	default:
		return "", fmt.Errorf("iampolicy: unsupported condition value of type %T", v)
	}
}

// StringOrArr handles JSON fields that can be either a string or an array of
// strings — the AWS shape for Action and Resource.
type StringOrArr []string

// UnmarshalJSON accepts either a JSON string or an array of strings. A JSON null
// yields a nil slice (an inert statement field) rather than [""].
func (s *StringOrArr) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = nil
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*s = arr
	return nil
}

// MarshalJSON marshals as a bare string when the slice has exactly one element,
// otherwise as an array — the AWS-compatible shape spinifex writes.
func (s StringOrArr) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}
