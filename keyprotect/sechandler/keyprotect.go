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

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	core "github.com/IBM/go-sdk-core/v5/core"
	kp "github.com/IBM/keyprotect-go-client/ibmkeyprotectapiv2"
	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
	"github.com/pkg/errors"
)

type keyprotectSecretKeyHandler struct {
	kpClient   *kp.IbmKeyProtectApiV2
	instanceID string
}

// handleSecret unwraps the keys by calling the key protect unwrap service, returning a
// map of key filenames to data to store. It returns a single key filename -> data map
// in the keyprotect implementation to meet the sechandlers.SecretKeyHandler func definition
func (skh *keyprotectSecretKeyHandler) handleSecret(data map[string][]byte) (map[string][]byte, error) {
	keyid, ok := data["rootkeyid"]
	if !ok {
		return nil, errors.New("rootkeyid not in secret")
	}

	ciphertext, ok := data["ciphertext"]
	if !ok {
		return nil, errors.New("ciphertext not in secret")
	}

	bodyJSON, err := json.Marshal(map[string]string{"ciphertext": string(ciphertext)})
	if err != nil {
		return nil, err
	}

	opts := skh.kpClient.NewUnwrapKeyOptions(
		string(keyid),
		skh.instanceID,
		io.NopCloser(strings.NewReader(string(bodyJSON))),
	)

	result, _, err := skh.kpClient.UnwrapKey(opts)
	if err != nil {
		return nil, err
	}

	if result.Plaintext == nil {
		return nil, errors.New("unwrap response contained no plaintext")
	}

	content, err := base64.StdEncoding.DecodeString(*result.Plaintext)
	if err != nil {
		return nil, err
	}

	return map[string][]byte{"kpkey": content}, nil
}

// NewKeyprotectSecretKeyHandler returns a secret handler for keyprotect given the keyprotect configuration
func NewKeyprotectSecretKeyHandler(kpUrl, instanceid, apikey string) (sechandlers.SecretKeyHandler, error) {
	auth := &core.IamAuthenticator{
		ApiKey: apikey,
	}

	kpClient, err := kp.NewIbmKeyProtectApiV2(&kp.IbmKeyProtectApiV2Options{
		URL:           kpUrl,
		Authenticator: auth,
	})
	if err != nil {
		return nil, err
	}

	kpskh := keyprotectSecretKeyHandler{
		kpClient:   kpClient,
		instanceID: instanceid,
	}

	return func(data map[string][]byte) (map[string][]byte, error) {
		return kpskh.handleSecret(data)
	}, nil
}
