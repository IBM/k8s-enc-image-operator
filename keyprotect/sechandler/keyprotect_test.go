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
	"net/http/httptest"
	"testing"

	core "github.com/IBM/go-sdk-core/v5/core"
	kp "github.com/IBM/keyprotect-go-client/ibmkeyprotectapiv2"
	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
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

// kpError responds with a Key Protect error with the given status code.
func kpError(status int, msg string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		respond(w, status, map[string]any{
			"metadata":  map[string]any{"collectionType": "application/vnd.ibm.kms.error+json", "collectionTotal": 1},
			"resources": []map[string]string{{"errorMsg": msg}},
		})
	}
}

func TestHandleSecretErrors(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("key"))})
	}

	tests := []struct {
		name      string
		data      map[string][]byte
		handle    http.HandlerFunc
		permanent bool
	}{
		{
			name:      "missing rootkeyid",
			data:      map[string][]byte{"ciphertext": []byte(testCiphertext)},
			handle:    ok,
			permanent: true,
		},
		{
			name:      "missing ciphertext",
			data:      map[string][]byte{"rootkeyid": []byte(testRootKeyID)},
			handle:    ok,
			permanent: true,
		},
		{
			name:      "invalid ciphertext",
			data:      validSecret(),
			handle:    kpError(http.StatusBadRequest, "Bad Request: The ciphertext provided for the unwrap operation was not wrapped by this key"),
			permanent: true,
		},
		{
			name:      "unauthorized",
			data:      validSecret(),
			handle:    kpError(http.StatusUnauthorized, "Unauthorized: The user does not have access to the specified resource"),
			permanent: true,
		},
		{
			name:      "forbidden",
			data:      validSecret(),
			handle:    kpError(http.StatusForbidden, "Forbidden: The user does not have access to the specified resource"),
			permanent: true,
		},
		{
			name:      "root key not found",
			data:      validSecret(),
			handle:    kpError(http.StatusNotFound, "Not Found: Key could not be found"),
			permanent: true,
		},
		{
			name:      "root key disabled",
			data:      validSecret(),
			handle:    kpError(http.StatusConflict, "Conflict: Key is disabled"),
			permanent: true,
		},
		{
			name:      "root key destroyed",
			data:      validSecret(),
			handle:    kpError(http.StatusGone, "Gone: Key has been deleted"),
			permanent: true,
		},
		{
			name:      "ciphertext not matching",
			data:      validSecret(),
			handle:    kpError(http.StatusUnprocessableEntity, "Unprocessable Entity: The ciphertext is invalid"),
			permanent: true,
		},
		{
			name:   "request timeout",
			data:   validSecret(),
			handle: kpError(http.StatusRequestTimeout, "Request Timeout"),
		},
		{
			name:   "rate limited",
			data:   validSecret(),
			handle: kpError(http.StatusTooManyRequests, "Too Many Requests"),
		},
		{
			name:   "server error",
			data:   validSecret(),
			handle: kpError(http.StatusInternalServerError, "Internal Server Error"),
		},
		{
			name:   "service unavailable",
			data:   validSecret(),
			handle: kpError(http.StatusServiceUnavailable, "Service Unavailable"),
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
			if p := sechandlers.IsPermanent(err); p != tt.permanent {
				t.Fatalf("expected permanent %v, got %v for error: %v", tt.permanent, p, err)
			}
		})
	}
}

// TestHandleSecretUnreachable checks that failing to reach Key Protect is a
// transient error.
func TestHandleSecretUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	client, err := kp.NewIbmKeyProtectApiV2(&kp.IbmKeyProtectApiV2Options{
		URL:           url,
		Authenticator: &core.NoAuthAuthenticator{},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.Service.DisableRetries()
	skh := &keyprotectSecretKeyHandler{kpClient: client, instanceID: testInstanceID}

	_, err = skh.handleSecret(validSecret())
	if err == nil {
		t.Fatal("expected an error")
	}
	if sechandlers.IsPermanent(err) {
		t.Fatalf("expected a transient error, got permanent: %v", err)
	}
}

// TestHandleSecretIAMErrors checks that errors getting an IAM token are
// classified by their status code as well, e.g. a deleted API key is a
// permanent error.
func TestHandleSecretIAMErrors(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		permanent bool
	}{
		{name: "api key not found", status: http.StatusBadRequest, permanent: true},
		{name: "rate limited", status: http.StatusTooManyRequests},
		{name: "server error", status: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iam := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				respond(w, tt.status, map[string]any{
					"errorCode":    "BXNIM0415E",
					"errorMessage": "Provided API key could not be found.",
				})
			}))
			t.Cleanup(iam.Close)
			unwrap := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				t.Error("unexpected unwrap request without a token")
			}))
			t.Cleanup(unwrap.Close)

			client, err := kp.NewIbmKeyProtectApiV2(&kp.IbmKeyProtectApiV2Options{
				URL:           unwrap.URL,
				Authenticator: &core.IamAuthenticator{ApiKey: "apikey", URL: iam.URL},
			})
			if err != nil {
				t.Fatal(err)
			}
			client.Service.DisableRetries()
			skh := &keyprotectSecretKeyHandler{kpClient: client, instanceID: testInstanceID}

			_, err = skh.handleSecret(validSecret())
			if err == nil {
				t.Fatal("expected an error")
			}
			if p := sechandlers.IsPermanent(err); p != tt.permanent {
				t.Fatalf("expected permanent %v, got %v for error: %v", tt.permanent, p, err)
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
