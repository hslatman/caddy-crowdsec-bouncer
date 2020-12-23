package utils

import (
	"bytes"
	"io/ioutil"
	"os"
	"unicode"

	"github.com/pkg/errors"
)

func maybeUnwrap(err error) error {
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return wrapped
	}
	return err
}

// ReadFile reads the file named by filename and returns the contents.
//
// It wraps ioutil.ReadFile wrapping the errors.
func ReadFile(filename string) ([]byte, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(maybeUnwrap(err), "error reading %s", filename)
	}
	return b, nil
}

// ReadPasswordFromFile reads and returns the password from the given filename.
// The contents of the file will be trimmed at the right.
func ReadPasswordFromFile(filename string) ([]byte, error) {
	password, err := ReadFile(filename)
	if err != nil {
		return nil, errors.Wrapf(err, "error reading %s", filename)
	}
	password = bytes.TrimRightFunc(password, unicode.IsSpace)
	return password, nil
}

// WriteFile writes data to a file named by filename.
// If the file does not exist, WriteFile creates it with permissions perm
// (before umask); otherwise WriteFile truncates it before writing.
//
// It wraps ioutil.WriteFile wrapping the errors.
func WriteFile(filename string, data []byte, perm os.FileMode) error {
	if err := ioutil.WriteFile(filename, data, perm); err != nil {
		return errors.Wrapf(maybeUnwrap(err), "error writing %s", filename)
	}
	return nil
}
