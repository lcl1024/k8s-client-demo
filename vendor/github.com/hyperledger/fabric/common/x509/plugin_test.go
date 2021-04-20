package x509

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitX509(t *testing.T) {
	ts := []struct {
		pluginName string
		wantErr    string
	}{
		{"", ""},
		{"std", ""},
		{"gmsm", ""},
		{"errorPlugin", "unrecognized x509 plugin type: errorPlugin"},
	}

	for _, c := range ts {
		err := InitX509(c.pluginName)
		if c.wantErr == "" {
			assert.NoError(t, err)
		} else {
			assert.EqualError(t, err, c.wantErr)
		}
	}
}
