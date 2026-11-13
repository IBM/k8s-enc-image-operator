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

package sechandlers

import (
	"reflect"
	"testing"
)

func TestRegularKeyHandler(t *testing.T) {
	for name, data := range map[string]map[string][]byte{
		"nil":      nil,
		"empty":    {},
		"one key":  {"a.pem": []byte("key a")},
		"two keys": {"a.pem": []byte("key a"), "b.pem": []byte("key b")},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := RegularKeyHandler(data)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, data) {
				t.Fatalf("expected the secret data unchanged %q, got %q", data, got)
			}
		})
	}
}
