// Copyright 2020, 2026 k8s-enc-image-operator authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sechandlers defines how the data of key secrets is turned into key
// files, and the handler for regular (type=key) secrets.
package sechandlers

import "errors"

// SecretKeyHandler is a function type that maps secret data into the
// filename/private key data to be stored. This is useful for handling
// secrets that may require an additional step of unwrapping, formatting, etc.
//
// If the handler fails, the key files previously synced from the secret are
// kept, unless the error is a PermanentError (see NewPermanentError).
type SecretKeyHandler func(map[string][]byte) (map[string][]byte, error)

// PermanentError marks a SecretKeyHandler error that retrying will not fix,
// e.g. the unwrapping service denied access or the secret is malformed. The
// key files previously synced from the secret are removed in that case, so
// that revoking access in the unwrapping service also revokes the keys on the
// nodes.
// Other errors are considered transient (e.g. the unwrapping service is
// unreachable) and the existing key files are kept until the handler
// succeeds again.
type PermanentError struct {
	Err error
}

func (e *PermanentError) Error() string {
	return e.Err.Error()
}

func (e *PermanentError) Unwrap() error {
	return e.Err
}

// NewPermanentError wraps err in a PermanentError. It returns nil if err is
// nil.
func NewPermanentError(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent returns true if err is or wraps a PermanentError.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}
