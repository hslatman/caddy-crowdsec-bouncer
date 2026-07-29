package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurrent(t *testing.T) {
	v := Current()

	assert.Equal(t, "v0.14.0", v) // fallback
}
