package suppressions

import (
	"reflect"
	"testing"

	"errors"
	"os"
	"syscall"

	"github.com/accurics/terrascan/pkg/config"
)

func TestSuppressionFile(t *testing.T) {

	table := []struct {
		name            string
		configFile      string
		wantErr         error
		compareAsString bool
	}{
		{
			name:       "config not present",
			configFile: "notthere",
			wantErr:    &os.PathError{Op: "open", Path: "notthere", Err: syscall.Errno(2)},
		},
		{
			name:            "invalid json",
			configFile:      "testdata/invalid.json",
			wantErr:         errors.New("invalid character 'T' looking for beginning of value"),
			compareAsString: true,
		},
		{
			name:       "bad format",
			configFile: "testdata/bad-format-suppressions.json",
			wantErr:    invalidFormatErr,
		},
		{
			name:       "invalid version",
			configFile: "testdata/invalid-version-suppressions.json",
			wantErr:    invalidFormatErr,
		},
		{
			name:       "invalid type",
			configFile: "testdata/invalid-type-suppressions.json",
			wantErr:    invalidFormatErr,
		},
		{
			name:       "valid file",
			configFile: "testdata/valid-suppressions.json",
			wantErr:    nil,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			config.Global.Policy.SuppressionPath = tt.configFile
			gotErr := LoadSuppressions()
			if tt.compareAsString {
				got := string(gotErr.Error())
				want := string(tt.wantErr.Error())
				if !reflect.DeepEqual(got, want) {
					t.Errorf("incorrect error; got: '%#v', want: '%#v'", got, want)
				}
			} else {
				if !reflect.DeepEqual(gotErr, tt.wantErr) {
					t.Errorf("incorrect error; got: '%#v', want: '%#v'", gotErr, tt.wantErr)
				}
			}
		})
	}
}
