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

package main

import (
	"context"
	"math"
	"os"
	"testing"
	"time"

	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestParseKeyFilePermissions(t *testing.T) {
	valid := map[string]os.FileMode{
		"0600": 0600,
		"600":  0600,
		"0":    0,
		"0777": 0777,
		"0440": 0440,
	}
	for in, want := range valid {
		got, err := parseKeyFilePermissions(in)
		if err != nil {
			t.Errorf("parseKeyFilePermissions(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseKeyFilePermissions(%q) = %v, want %v", in, got, want)
		}
	}

	for _, in := range []string{"", "abc", "0800", "0600x", "-600", "01000", "4755"} {
		if _, err := parseKeyFilePermissions(in); err == nil {
			t.Errorf("parseKeyFilePermissions(%q): expected an error", in)
		}
	}
}

func TestParseKeyFileOwnership(t *testing.T) {
	uid, gid, err := parseKeyFileOwnership("")
	if err != nil || uid != nil || gid != nil {
		t.Fatalf(`parseKeyFileOwnership(""): expected nil, nil, nil, got %v, %v, %v`, uid, gid, err)
	}

	uid, gid, err = parseKeyFileOwnership("1000:2000")
	if err != nil {
		t.Fatal(err)
	}
	if uid == nil || gid == nil || *uid != 1000 || *gid != 2000 {
		t.Fatalf(`parseKeyFileOwnership("1000:2000"): got %v, %v`, uid, gid)
	}

	uid, gid, err = parseKeyFileOwnership("0:0")
	if err != nil || *uid != 0 || *gid != 0 {
		t.Fatalf(`parseKeyFileOwnership("0:0"): got %v, %v, %v`, uid, gid, err)
	}

	for _, in := range []string{"1000", "1000:", ":1000", "a:b", "-1:0", "0:-1", "1000:2000x", "1:2:3"} {
		if _, _, err := parseKeyFileOwnership(in); err == nil {
			t.Errorf("parseKeyFileOwnership(%q): expected an error", in)
		}
	}
}

func TestParseInterval(t *testing.T) {
	got, err := parseInterval(10)
	if err != nil || got != 10*time.Second {
		t.Fatalf("parseInterval(10) = %v, %v", got, err)
	}

	maxSeconds := uint(math.MaxInt64 / time.Second)
	if _, err := parseInterval(maxSeconds); err != nil {
		t.Fatalf("parseInterval(%d): unexpected error %v", maxSeconds, err)
	}
	// One more second would overflow time.Duration into a negative value,
	// which time.After treats as "fire immediately".
	if _, err := parseInterval(maxSeconds + 1); err == nil {
		t.Fatalf("parseInterval(%d): expected an error", maxSeconds+1)
	}
}

const (
	testNamespace  = "default"
	testSecretName = "kp-config"
	validKPConfig  = `{"keyprotect-url": "https://us-south.kms.cloud.ibm.com", "instance-id": "instance", "apikey": "apikey"}`
)

// recordingAddHandler records the secret types handlers were registered for.
type recordingAddHandler struct {
	types []string
}

func (r *recordingAddHandler) add(secretType string, skh sechandlers.SecretKeyHandler) {
	if skh == nil {
		panic("nil handler registered")
	}
	r.types = append(r.types, secretType)
}

func setKPConfigSecret(t *testing.T, client *fake.Clientset, data map[string][]byte) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
		Data:       data,
	}
	secClient := client.CoreV1().Secrets(testNamespace)
	_, err := secClient.Update(context.Background(), secret, metav1.UpdateOptions{})
	if err != nil {
		_, err = secClient.Create(context.Background(), secret, metav1.CreateOptions{})
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSyncKeyprotectConfig(t *testing.T) {
	client := fake.NewClientset()
	rec := &recordingAddHandler{}
	sync := func(oldData string) string {
		return syncKeyprotectConfig(client, testNamespace, testSecretName, rec.add, oldData)
	}

	// Secret does not exist yet.
	data := sync("")
	if data != "" || len(rec.types) != 0 {
		t.Fatalf("expected no handler without secret, got data %q, handlers %v", data, rec.types)
	}

	// Secret without config.json.
	setKPConfigSecret(t, client, map[string][]byte{"other": []byte("x")})
	data = sync(data)
	if data != "" || len(rec.types) != 0 {
		t.Fatalf("expected no handler without config.json, got data %q, handlers %v", data, rec.types)
	}

	// Valid config registers the kp-key handler.
	setKPConfigSecret(t, client, map[string][]byte{"config.json": []byte(validKPConfig)})
	data = sync(data)
	if data != validKPConfig || len(rec.types) != 1 || rec.types[0] != "kp-key" {
		t.Fatalf("expected kp-key handler, got data %q, handlers %v", data, rec.types)
	}

	// Unchanged config does not register again.
	data = sync(data)
	if len(rec.types) != 1 {
		t.Fatalf("expected no new handler for unchanged config, got %v", rec.types)
	}

	// Invalid config is remembered but not registered.
	setKPConfigSecret(t, client, map[string][]byte{"config.json": []byte("{not json")})
	data = sync(data)
	if data != "{not json" || len(rec.types) != 1 {
		t.Fatalf("expected no handler for invalid config, got data %q, handlers %v", data, rec.types)
	}

	// Config with a missing apikey fails validation and is not registered.
	setKPConfigSecret(t, client, map[string][]byte{"config.json": []byte(`{"instance-id": "instance"}`)})
	data = sync(data)
	if len(rec.types) != 1 {
		t.Fatalf("expected no handler for config without apikey, got %v", rec.types)
	}

	// A fixed config is picked up again.
	setKPConfigSecret(t, client, map[string][]byte{"config.json": []byte(validKPConfig)})
	data = sync(data)
	if data != validKPConfig || len(rec.types) != 2 {
		t.Fatalf("expected handler for fixed config, got data %q, handlers %v", data, rec.types)
	}

	// The secret being deleted keeps the current handler.
	if err := client.CoreV1().Secrets(testNamespace).Delete(context.Background(), testSecretName, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := sync(data); got != data || len(rec.types) != 2 {
		t.Fatalf("expected no change after secret deletion, got data %q, handlers %v", got, rec.types)
	}
}
