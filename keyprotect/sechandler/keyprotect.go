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
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
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
// Errors that retrying will not fix, i.e. a malformed secret or the request
// being rejected (see isPermanentStatus), are returned as
// sechandlers.PermanentError, so that the keys synced before are removed.
func (skh *keyprotectSecretKeyHandler) handleSecret(data map[string][]byte) (map[string][]byte, error) {
	keyid, ok := data["rootkeyid"]
	if !ok {
		return nil, sechandlers.NewPermanentError(errors.New("rootkeyid not in secret"))
	}

	ciphertext, ok := data["ciphertext"]
	if !ok {
		return nil, sechandlers.NewPermanentError(errors.New("ciphertext not in secret"))
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

	// The response is also set if the request was rejected by IAM while
	// getting a token, e.g. because the API key was deleted.
	result, resp, err := skh.kpClient.UnwrapKey(opts)
	if err != nil {
		if resp != nil && isPermanentStatus(resp.StatusCode) {
			return nil, sechandlers.NewPermanentError(err)
		}
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

// isPermanentStatus returns true if a request failing with the given HTTP
// status code would fail the same way when retried. That is the case for
// client errors, e.g. access denied (401, 403), the root key deleted (404,
// 410), disabled (409) or not matching the ciphertext (400, 422), except for
// a request timeout (408) and rate limiting (429). Server errors and failures
// without a response (e.g. the service is unreachable) are transient.
func isPermanentStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return statusCode >= 400 && statusCode < 500
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
