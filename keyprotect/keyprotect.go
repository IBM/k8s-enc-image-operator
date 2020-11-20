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

package keyprotect

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	kpsh "github.com/lumjjb/k8s-enc-image-operator/keyprotect/sechandler"
	sechandlers "github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
)

// keyprotectConfig example, is a json in the following format
// {
//     "keyprotect-url": "https://us-south.kms.cloud.ibm.com",
//     "instance-id": "a3c5e3g5-9ef7-4838-a285-398efb23e6f3",
//     "apikey": "ZWh0YWVyZwbvHwo-345mfwSOST6wtdMFqeLcdE4Tsxbz",
// }
type keyprotectConfig struct {
	KeyprotectUrl string `json:"keyprotect-url"`
	InstanceId    string `json:"instance-id"`
	Apikey        string `json:"apikey"`
}

// GetSecKeyHandlerFromConfig returns a secrethandler for key protect given a configuration
// file for key protect
func GetSecKeyHandlerFromConfig(kpconfigPath string) (sechandlers.SecretKeyHandler, error) {
	data, err := ioutil.ReadFile(filepath.Clean(kpconfigPath))
	if err != nil {
		return nil, err
	}

	var kpc keyprotectConfig
	err = json.Unmarshal(data, &kpc)
	if err != nil {
		return nil, err
	}

	secHandler, err := kpsh.NewKeyprotectSecretKeyHandler(kpc.KeyprotectUrl,
		kpc.InstanceId,
		kpc.Apikey)
	if err != nil {
		return nil, err
	}

	return secHandler, nil
}
