package suppressions

import (
	"crypto/sha1"
	"fmt"

	"github.com/accurics/terrascan/pkg/iac-providers/output"
)

// SuppressedHashesSet is used to look up suppressed hashes
type SuppressedHashesSet map[string]bool

// Add a hash to the SuppressedHashesSet
func (s *SuppressedHashesSet) Add(hash string) error {
	(*s)[hash] = true
	return nil
}

// Get determines whether a hash is in the SuppressedHashesSet
func (s SuppressedHashesSet) Get(hash string) bool {
	if _, found := s[hash]; found {
		return true
	}
	return false
}

// MakeHash computes a stable hash for a particular finding, which can be used to suppress specific findings in the output
func MakeHash(ruleName string, resource *output.ResourceConfig) string {
	sep := []byte("^")

	h := sha1.New()

	h.Write([]byte(ruleName))
	h.Write(sep)
	h.Write([]byte(resource.Locator))
	h.Write(sep)
	h.Write([]byte(resource.Type))

	hash := h.Sum(nil)

	return fmt.Sprintf("%x", hash)
}
