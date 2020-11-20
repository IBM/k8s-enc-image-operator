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

// SecretKeyHandler is a function type that maps secret data into the
// filename/private key data to be stored. This is useful for handling
// secrets that may require an additional step of unwrapping, formatting, etc.
type SecretKeyHandler func(map[string][]byte) (map[string][]byte, error)
