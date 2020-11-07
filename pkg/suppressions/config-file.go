package suppressions

import (
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/accurics/terrascan/pkg/config"

	"go.uber.org/zap"
)

const (
	fileTypeString                = string("terrascan-suppression-list")
	highestSupportedFormatVersion = int(1)
	invalidFormatErr              = constError("invalid format")
)

type constError string

func (err constError) Error() string {
	return string(err)
}

// SuppressionDefinitions holds the configured suppressions
type SuppressionDefinitions struct {
	Hashes  []string            `json:"hashes"`
	HashSet SuppressedHashesSet `json:"-"`
}

// suppressionsFile is used to read the suppressions config file
type suppressionsFile struct {
	FileType      string                 `json:"type"`
	FormatVersion int                    `json:"format-version"`
	Suppressions  SuppressionDefinitions `json:"suppressions"`
}

// The global list of all suppressions
var allSuppressions SuppressionDefinitions

// LoadSuppressions loads the suppression list
func LoadSuppressions() error {

	// If no path is configured, return immediately
	filename := config.GetSuppressionPath()
	if len(filename) == 0 {
		return nil
	}

	zap.S().Debugf("reading suppressions from %v", filename)
	s, err := ioutil.ReadFile(filename)
	if err != nil {
		zap.S().Warnf("error reading suppressions: %v", err)
		return err
	}

	suppressions := suppressionsFile{}
	err = json.Unmarshal(s, &suppressions)
	if err != nil {
		zap.S().Errorf("unmarshal error: %v", err)
		return err
	}

	// Make sure it looks familiar
	if suppressions.FileType != fileTypeString || suppressions.FormatVersion < 0 || suppressions.FormatVersion > highestSupportedFormatVersion {
		zap.S().Errorf(invalidFormatErr.Error())
		return invalidFormatErr
	}

	// Load the suppressedd hashes into a SuppressedHashesSet
	suppressed := make(SuppressedHashesSet)
	for _, hash := range suppressions.Suppressions.Hashes {
		hash = strings.TrimSpace(hash)
		if len(hash) == 0 {
			continue
		}
		zap.S().Debugf("suppress hash %s", hash)
		suppressed.Add(hash)
	}
	suppressions.Suppressions.HashSet = suppressed

	allSuppressions = suppressions.Suppressions

	return nil
}
