package suppressions

import (
	"testing"

	"github.com/accurics/terrascan/pkg/iac-providers/output"
)

func TestSuppressions(t *testing.T) {

	ruleName := "myRuleName"
	table := []output.ResourceConfig{
		{
			Locator: "logical.path.to.resource",
			Type:    "resource_type",
		},
		{
			Locator: "logical.path.to.resource",
			Type:    "resource_type2",
		},
		{
			Locator: "logical.path.to.other.resource",
			Type:    "resource_type2",
		},
		{
			Locator: "logical.path.to.other.resource",
			Type:    "resource_type",
		},
	}

	t.Run("findingsSuppressedProperly", func(t *testing.T) {
		suppressions := SuppressedHashesSet{}
		suppressions.Add(MakeHash(ruleName, &table[0]))
		for i, tt := range table {
			if i == 0 {
				if !suppressions.Get(MakeHash(ruleName, &tt)) {
					t.Errorf("index %d should be suppressed but is not", i)
				}
			} else {
				if suppressions.Get(MakeHash(ruleName, &tt)) {
					t.Errorf("index %d incorrectly suppressed", i)
				}
			}
		}
	})
}
