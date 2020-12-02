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
	"context"
	"encoding/base64"
	kp "github.com/IBM/keyprotect-go-client"
	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
	"github.com/pkg/errors"
)

type keyprotectSecretKeyHandler struct {
	kpClient *kp.Client
}

// handleSecret unwraps the keys by calling the key protect unwrap service
func (skh *keyprotectSecretKeyHandler) handleSecret(data map[string][]byte) (map[string][]byte, error) {
	var err error
	retdata := map[string][]byte{}

	keyid, ok := data["keyid"]
	if !ok {
		return nil, errors.New("keyid not in secret")
	}

	ciphertext, ok := data["ciphertext"]
	if !ok {
		return nil, errors.New("ciphertext not in secret")
	}

	b64content, err := skh.kpClient.Unwrap(context.TODO(), string(keyid), ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var content []byte
	content, err = base64.StdEncoding.DecodeString(string(b64content))
	if err != nil {
		return nil, err
	}

	retdata["kpkey"] = content

	return retdata, nil
}

// NewKeyprotectSecretKeyHandler returns a secret handler for keyprotect given the keyprotect configuration
func NewKeyprotectSecretKeyHandler(kpUrl, instanceid, apikey string) (sechandlers.SecretKeyHandler, error) {
	cc := kp.ClientConfig{
		BaseURL:    kpUrl,
		APIKey:     apikey,
		InstanceID: instanceid,
	}

	kpClient, err := kp.New(cc, kp.DefaultTransport())
	if err != nil {
		return nil, err
	}

	kpskh := keyprotectSecretKeyHandler{
		kpClient: kpClient,
	}

	return func(data map[string][]byte) (map[string][]byte, error) {
		return kpskh.handleSecret(data)
	}, nil
}
