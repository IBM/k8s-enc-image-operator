// Copyright 2026 k8s-enc-image-operator authors.
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

package sechandlers

import (
	"errors"
	"fmt"
	"testing"
)

func TestPermanentError(t *testing.T) {
	base := errors.New("access denied")
	err := NewPermanentError(base)

	if err.Error() != base.Error() {
		t.Errorf("expected message %q, got %q", base.Error(), err.Error())
	}
	if !errors.Is(err, base) {
		t.Error("expected the permanent error to wrap the original error")
	}
	if !IsPermanent(err) {
		t.Error("expected a permanent error")
	}
	if !IsPermanent(fmt.Errorf("unwrapping: %w", err)) {
		t.Error("expected a wrapped permanent error to be permanent")
	}
	if IsPermanent(base) {
		t.Error("expected a plain error not to be permanent")
	}
	if IsPermanent(nil) {
		t.Error("expected nil not to be permanent")
	}
	if NewPermanentError(nil) != nil {
		t.Error("expected NewPermanentError(nil) to return nil")
	}
}
