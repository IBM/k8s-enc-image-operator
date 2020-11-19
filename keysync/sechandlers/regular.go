// Copyright 2020 k8s-enc-image-operator authors.
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

var (
	// RegularKeyHandler handles keys with type secret=key
	// In this case, each entry represents a file and the private key data
	// so no action is required.
	RegularKeyHandler SecretKeyHandler = func(data map[string][]byte) (map[string][]byte, error) {
		return data, nil
	}
)
