package suppressions

import (
	"github.com/accurics/terrascan/pkg/iac-providers/output"
)

// IsSuppressed returns true if the violation should be suppressed
func IsSuppressed(ruleName string, resource *output.ResourceConfig) bool {

	// TODO: add more filtering options, based on a combination of things:
	// rule name (ruleName)
	// resource.ID, which is often resource.Type+"."+resource.Name
	// name (resource.Name)
	// module hierarchy (resource.Locator)
	// filesystem path (resource.Source); focus on directories, not filenames
	// resource type (resource.Type)

	return allSuppressions.HashSet.Get(MakeHash(ruleName, resource))

}

// ShouldNotBeScanned returns true if a particular location should not be scanned.  Currently returns false in all cases.
func ShouldNotBeScanned(ruleName string, resourceMap *output.AllResourceConfigs) bool {
	// This function is a placeholder, to allow us to avoid evaluating a rule on the resourceMap passed as an argument.
	// We should only return true if the entire resourceMap should not be evaluated against the policy.

	return false
}
