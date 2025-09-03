package utils

import (
	"os"
	"testing"

	"gotest.tools/v3/assert"
)

func TestReadFile(t *testing.T) {
	// Setup
	file, err := os.Create("/tmp/tinyauth_test_file")
	assert.NilError(t, err)

	_, err = file.WriteString("file content\n")
	assert.NilError(t, err)

	err = file.Close()
	assert.NilError(t, err)
	defer os.Remove("/tmp/tinyauth_test_file")

	// Normal case
	content, err := ReadFile("/tmp/tinyauth_test_file")
	assert.NilError(t, err)
	assert.Equal(t, "file content\n", content)

	// Non-existing file
	content, err = ReadFile("/tmp/non_existing_file")
	assert.ErrorContains(t, err, "no such file or directory")
	assert.Equal(t, "", content)
}
