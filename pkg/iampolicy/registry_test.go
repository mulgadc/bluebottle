package iampolicy_test

import (
	"testing"

	"github.com/mulgadc/bluebottle/pkg/iampolicy"
	"github.com/stretchr/testify/assert"
)

// Every condition key the package names. The two registries behind it are
// unexported, so this list stands in for them; the door key sets in door_test.go
// keep it honest, and the probes below read the registries through the exported
// API rather than restating what is in them.
var allConditionKeys = []string{
	iampolicy.KeySourceIP,
	iampolicy.KeyS3Prefix,
	iampolicy.KeySecureTransport,
	iampolicy.KeyUsername,
	iampolicy.KeyPrincipalAccount,
	iampolicy.KeyUserID,
}

// Every operator the package names. conditions_internal_test.go pins that the
// matcher implements exactly the set the allowlist advertises, so this list only
// has to cover the operators a policy can be written with.
var allOperators = []string{
	iampolicy.OpStringEquals,
	iampolicy.OpStringLike,
	iampolicy.OpIPAddress,
	iampolicy.OpBool,
}

// Empty on purpose: every substitutable key is supplied by a door, so the gate
// below has no excuses left to grant. Adding a key here admits a reference that
// is unresolvable everywhere, where an Allow grants nothing and a Deny fires
// against every resource — say why, or supply the key at a door instead.
var variablesNoDoorSupplies = map[string]string{}

// conditionKey reports whether any operator enforces key.
func conditionKey(key string) bool {
	for _, op := range allOperators {
		if iampolicy.SupportedCondition(op, key) {
			return true
		}
	}
	return false
}

// substitutable reports whether ${key} is a reference the evaluator can resolve,
// asked of the registry itself rather than of a copy of it.
func substitutable(key string) bool {
	_, unsupported := iampolicy.UnsupportedVariable("${" + key + "}")
	return !unsupported
}

// suppliedKeys is every key some door in the door table resolves.
func suppliedKeys() map[string]string {
	supplied := make(map[string]string)
	for _, d := range doors {
		for key := range d.keys {
			supplied[key] = d.name
		}
	}
	return supplied
}

// A key a door supplies but neither registry knows is a key no policy can ever
// use — it is carried to the evaluator and dropped there.
func TestRegistries_EverySuppliedKeyIsUsableInAPolicy(t *testing.T) {
	for key, door := range suppliedKeys() {
		assert.True(t, conditionKey(key) || substitutable(key),
			"door %q supplies %q, which is neither in supportedConditions nor substitutable: "+
				"a policy naming it can never fire", door, key)
	}
}

// The mirror direction: a supported key no door resolves is a grant that never
// fires, which is why aws:MultiFactorAuthPresent was left out of the allowlist.
func TestRegistries_EverySupportedKeyIsSuppliedByADoor(t *testing.T) {
	supplied := suppliedKeys()
	for _, key := range allConditionKeys {
		if !conditionKey(key) {
			continue
		}
		_, ok := supplied[key]
		assert.True(t, ok,
			"%q is enforced by supportedConditions but no door supplies it, so a condition on it "+
				"is inert everywhere", key)
	}
}

// The same question for the variable registry, which is a different set on
// purpose. Its one unresolvable member is named rather than skipped, so both
// halves of the gate move only deliberately.
func TestRegistries_EverySubstitutableKeyIsSuppliedByADoor(t *testing.T) {
	supplied := suppliedKeys()
	for _, key := range allConditionKeys {
		if !substitutable(key) {
			continue
		}
		_, ok := supplied[key]
		reason, excused := variablesNoDoorSupplies[key]
		assert.Equal(t, ok, !excused,
			"%q is substitutable: either a door supplies it or variablesNoDoorSupplies gives a reason "+
				"(%q), and it cannot be both or neither", key, reason)
	}

	for key := range variablesNoDoorSupplies {
		assert.True(t, substitutable(key),
			"variablesNoDoorSupplies names %q, which is not a substitutable key: remove it", key)
	}
}

// The key list this file reasons over has to cover what the doors carry, or the
// two tests above quietly stop checking a key.
func TestRegistries_KeyListCoversEveryDoor(t *testing.T) {
	known := make(map[string]bool, len(allConditionKeys))
	for _, key := range allConditionKeys {
		known[key] = true
	}
	for key, door := range suppliedKeys() {
		assert.True(t, known[key],
			"door %q supplies %q, which allConditionKeys does not list: add it", door, key)
	}
}
