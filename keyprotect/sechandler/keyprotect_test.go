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
	"net/http"
	"net/http/httptest"
	"testing"

	core "github.com/IBM/go-sdk-core/v5/core"
	kp "github.com/IBM/keyprotect-go-client/ibmkeyprotectapiv2"
)

const (
	testInstanceID = "test-instance"
	testRootKeyID  = "test-root-key"
	testCiphertext = "wrapped-ciphertext"
)

// newTestHandler returns a handler talking to a fake Key Protect server that
// answers unwrap requests with handle. Authentication is disabled so no
// request is sent to IAM.
func newTestHandler(t *testing.T, handle http.HandlerFunc) *keyprotectSecretKeyHandler {
	t.Helper()
	srv := httptest.NewServer(handle)
	t.Cleanup(srv.Close)

	client, err := kp.NewIbmKeyProtectApiV2(&kp.IbmKeyProtectApiV2Options{
		URL:           srv.URL,
		Authenticator: &core.NoAuthAuthenticator{},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.Service.DisableRetries()
	return &keyprotectSecretKeyHandler{kpClient: client, instanceID: testInstanceID}
}

// respond writes body as a JSON response with the given status code.
func respond(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func validSecret() map[string][]byte {
	return map[string][]byte{
		"rootkeyid":  []byte(testRootKeyID),
		"ciphertext": []byte(testCiphertext),
	}
}

func TestHandleSecret(t *testing.T) {
	plaintext := []byte("this is a private key")

	skh := newTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if want := "/api/v2/keys/" + testRootKeyID + "/actions/unwrap"; r.URL.Path != want {
			t.Errorf("expected path %s, got %s", want, r.URL.Path)
		}
		if got := r.Header.Get("Bluemix-Instance"); got != testInstanceID {
			t.Errorf("expected Bluemix-Instance %q, got %q", testInstanceID, got)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var req map[string]string
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("request body is not JSON: %v: %s", err, body)
		}
		if req["ciphertext"] != testCiphertext {
			t.Errorf("expected ciphertext %q, got %q", testCiphertext, req["ciphertext"])
		}

		respond(w, http.StatusOK, map[string]string{
			"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		})
	})

	got, err := skh.handleSecret(validSecret())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got["kpkey"]) != string(plaintext) {
		t.Fatalf("expected {kpkey: %q}, got %q", plaintext, got)
	}
}

func TestHandleSecretErrors(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("key"))})
	}

	tests := []struct {
		name   string
		data   map[string][]byte
		handle http.HandlerFunc
	}{
		{
			name:   "missing rootkeyid",
			data:   map[string][]byte{"ciphertext": []byte(testCiphertext)},
			handle: ok,
		},
		{
			name:   "missing ciphertext",
			data:   map[string][]byte{"rootkeyid": []byte(testRootKeyID)},
			handle: ok,
		},
		{
			name: "unwrap fails",
			data: validSecret(),
			handle: func(w http.ResponseWriter, _ *http.Request) {
				respond(w, http.StatusNotFound, map[string]any{
					"metadata":  map[string]any{"collectionType": "application/vnd.ibm.kms.error+json", "collectionTotal": 1},
					"resources": []map[string]string{{"errorMsg": "Not Found: Key could not be found"}},
				})
			},
		},
		{
			name: "no plaintext in response",
			data: validSecret(),
			handle: func(w http.ResponseWriter, _ *http.Request) {
				respond(w, http.StatusOK, map[string]string{})
			},
		},
		{
			name: "plaintext not base64",
			data: validSecret(),
			handle: func(w http.ResponseWriter, _ *http.Request) {
				respond(w, http.StatusOK, map[string]string{"plaintext": "not base64!"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skh := newTestHandler(t, tt.handle)
			got, err := skh.handleSecret(tt.data)
			if err == nil {
				t.Fatalf("expected an error, got %q", got)
			}
		})
	}
}

func TestNewKeyprotectSecretKeyHandler(t *testing.T) {
	skh, err := NewKeyprotectSecretKeyHandler("https://us-south.kms.cloud.ibm.com", testInstanceID, "apikey")
	if err != nil {
		t.Fatal(err)
	}
	if skh == nil {
		t.Fatal("expected a handler")
	}

	// The returned handler validates the secret before contacting any
	// service, so this does not need network access.
	if _, err := skh(map[string][]byte{}); err == nil {
		t.Fatal("expected an error for a secret without rootkeyid")
	}
}

func TestNewKeyprotectSecretKeyHandlerErrors(t *testing.T) {
	tests := []struct {
		name, url, apikey string
	}{
		{name: "missing apikey", url: "https://us-south.kms.cloud.ibm.com", apikey: ""},
		{name: "apikey with quotes", url: "https://us-south.kms.cloud.ibm.com", apikey: `"apikey"`},
		{name: "url with braces", url: "{https://us-south.kms.cloud.ibm.com}", apikey: "apikey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewKeyprotectSecretKeyHandler(tt.url, testInstanceID, tt.apikey); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
