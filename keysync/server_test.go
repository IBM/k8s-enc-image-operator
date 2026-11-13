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

package keysync

import (
	"context"
	"crypto/md5" // #nosec G501 Usage is not related to security
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
)

const testNamespace = "default"

// staleKeyFile is the name of a key file synced from a secret that no longer
// exists.
var staleKeyFile = getLocalKeyFilename(testNamespace, "old-secret", "key", "0123456789abcdef0123456789abcdef")

// legacyKeyFile returns the file name previous versions used for one entry of
// a secret: <md5>-namespace-secretName-filename.
func legacyKeyFile(secret, entry, content string) string {
	hash := fmt.Sprintf("%x", md5.Sum([]byte(content))) // #nosec G401 Needed only to check if file exists
	return fmt.Sprintf("%s-%s-%s-%s", hash, testNamespace, secret, entry)
}

// newTestClient returns a fake clientset that honours the "type=<secret
// type>" field selector the server lists with. The stock fake client ignores
// field selectors (https://github.com/kubernetes/kubernetes/issues/78824),
// which would make every handler see every secret.
func newTestClient() *fake.Clientset {
	client := fake.NewClientset()
	client.PrependReactor("list", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
		la := action.(coretesting.ListAction)
		obj, err := client.Tracker().List(
			corev1.SchemeGroupVersion.WithResource("secrets"),
			corev1.SchemeGroupVersion.WithKind("Secret"),
			la.GetNamespace())
		if err != nil {
			return true, nil, err
		}
		list := obj.(*corev1.SecretList)
		sel := la.GetListRestrictions().Fields
		filtered := &corev1.SecretList{ListMeta: list.ListMeta}
		for _, s := range list.Items {
			if sel == nil || sel.Matches(fields.Set{"type": string(s.Type)}) {
				filtered.Items = append(filtered.Items, s)
			}
		}
		return true, filtered, nil
	})
	return client
}

// newTestServer returns a server syncing into dir. Tests drive it by calling
// syncOnce directly instead of running Start and sleeping on the interval.
func newTestServer(client *fake.Clientset, dir string, perm os.FileMode) *KeySyncServer {
	return NewKeySyncServer(KeySyncServerConfig{
		K8sClient:          client,
		Interval:           time.Hour,
		KeySyncDir:         dir,
		Namespace:          testNamespace,
		KeyFilePermissions: perm,
	})
}

// readDir returns the key files in dir as filename -> content.
func readDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = string(data)
	}
	return files
}

// expectFiles asserts that dir contains exactly the given filename -> content.
func expectFiles(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	got := readDir(t, dir)
	if len(got) != len(want) {
		t.Fatalf("expected %d key files %v, got %d: %v", len(want), want, len(got), got)
	}
	for name, content := range want {
		c, ok := got[name]
		if !ok {
			t.Fatalf("expected key file %q, got %v", name, got)
		}
		if c != content {
			t.Fatalf("key file %q: expected content %q, got %q", name, content, c)
		}
	}
}

// keyFile returns the file name the server uses for one entry of a secret.
func keyFile(secret, entry, content string) string {
	hash := fmt.Sprintf("%x", md5.Sum([]byte(content))) // #nosec G401 Needed only to check if file exists
	return getLocalKeyFilename(testNamespace, secret, entry, hash)
}

func createSecret(t *testing.T, client *fake.Clientset, name, secType string, data map[string][]byte) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Data:       data,
		Type:       corev1.SecretType(secType),
	}
	if _, err := client.CoreV1().Secrets(testNamespace).Create(context.Background(), secret, metav1.CreateOptions{}); err != nil {
		t.Fatalf("Unable to create secret: %v", err)
	}
}

func updateSecret(t *testing.T, client *fake.Clientset, name, secType string, data map[string][]byte) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Data:       data,
		Type:       corev1.SecretType(secType),
	}
	if _, err := client.CoreV1().Secrets(testNamespace).Update(context.Background(), secret, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("Unable to update secret: %v", err)
	}
}

func deleteSecret(t *testing.T, client *fake.Clientset, name string) {
	t.Helper()
	if err := client.CoreV1().Secrets(testNamespace).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
}

func base64SecretHandler(data map[string][]byte) (map[string][]byte, error) {
	retmap := map[string][]byte{}
	for k, v := range data {
		s, err := base64.StdEncoding.DecodeString(string(v))
		if err != nil {
			return nil, err
		}
		retmap[k] = s
	}
	return retmap, nil
}

// TestKeySync runs through syncing of a key for creation and deletion of a key
func TestKeySync(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)

	ks.syncOnce()
	expectFiles(t, dir, map[string]string{})

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})

	deleteSecret(t, client, "my-secret")
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{})
}

func TestKeySyncIgnoresOtherSecretTypes(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)

	createSecret(t, client, "opaque", string(corev1.SecretTypeOpaque), map[string][]byte{"a": []byte("not a key")})
	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()

	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})
}

func TestKeySyncMultipleSecretsAndEntries(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)

	createSecret(t, client, "s1", "key", map[string][]byte{
		"a.pem": []byte("key a"),
		"b.pem": []byte("key b"),
	})
	createSecret(t, client, "s2", "key", map[string][]byte{"a.pem": []byte("key c")})
	ks.syncOnce()

	expectFiles(t, dir, map[string]string{
		keyFile("s1", "a.pem", "key a"): "key a",
		keyFile("s1", "b.pem", "key b"): "key b",
		keyFile("s2", "a.pem", "key c"): "key c",
	})

	// Deleting one secret only removes its own files.
	deleteSecret(t, client, "s1")
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("s2", "a.pem", "key c"): "key c",
	})
}

// TestKeySyncSecretUpdate checks that rotating a key replaces the old file,
// so the revoked key does not stay on disk.
func TestKeySyncSecretUpdate(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("old key")})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "old key"): "old key",
	})

	updateSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("new key")})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "new key"): "new key",
	})
}

// TestKeySyncRemovesUntrackedFiles checks that files not belonging to any
// current secret, e.g. left over from a previous run, are removed.
func TestKeySyncRemovesUntrackedFiles(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()

	stale := filepath.Join(dir, staleKeyFile)
	if err := os.WriteFile(stale, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}

	ks := newTestServer(client, dir, 0600)
	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()

	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})
}

// TestKeySyncKeepsUnmanagedFiles checks that cleanup only removes key files
// written by the server and stale temporary files, and leaves everything
// else in the sync directory alone, e.g. when it is shared with keys
// configured manually.
func TestKeySyncKeepsUnmanagedFiles(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()

	unmanaged := map[string]string{
		"my-manual-key.pem":                 "manual",
		"0123-default-old-secret-key":       "short hash",
		"0123_default_old-secret_key":       "short hash",
		strings.ToUpper(staleKeyFile):       "upper case hash",
		staleKeyFile[:keyFileHashLen] + "_": "nothing after hash",
		staleKeyFile[:keyFileHashLen] + "-": "nothing after hash (legacy)",
		staleKeyFile[:keyFileHashLen] + ".": "other separator",
		"x" + staleKeyFile:                  "prefixed",
		".hidden":                           "hidden",
	}
	for name, content := range unmanaged {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, staleKeyFile), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, legacyKeyFile("old-secret", "key", "old")), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, tempFilePrefix+"123"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	// A directory with a managed name is not removed either.
	if err := os.Mkdir(filepath.Join(dir, keyFile("subdir", "k", "v")), 0700); err != nil {
		t.Fatal(err)
	}

	ks := newTestServer(client, dir, 0600)
	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range entries {
		got[e.Name()] = true
	}
	want := map[string]bool{
		keyFile("my-secret", "mykey", "this is a key"): true,
		keyFile("subdir", "k", "v"):                    true,
	}
	for name := range unmanaged {
		want[name] = true
	}
	if len(got) != len(want) {
		t.Fatalf("expected files %v, got %v", want, got)
	}
	for name := range want {
		if !got[name] {
			t.Fatalf("expected file %q to exist, got %v", name, got)
		}
	}
}

// TestKeySyncNoTempFilesLeft checks that writing a key leaves no temporary
// files behind.
func TestKeySyncNoTempFilesLeft(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0640)

	createSecret(t, client, "my-secret", "key", map[string][]byte{
		"a": []byte("key a"),
		"b": []byte("key b"),
	})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "a", "key a"): "key a",
		keyFile("my-secret", "b", "key b"): "key b",
	})
}

// TestKeySyncKeepsKeysWhenHandlerFails checks that a secret that still exists
// but cannot be processed, e.g. because the unwrapping service is
// unreachable, keeps its already-synced keys, while keys of deleted secrets
// are still removed.
func TestKeySyncKeepsKeysWhenHandlerFails(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()

	var failHandler atomic.Bool
	ks := newTestServer(client, dir, 0600)
	ks.AddSecretKeyHandler("base64-key", func(data map[string][]byte) (map[string][]byte, error) {
		if failHandler.Load() {
			return nil, errors.New("unwrapping service unavailable")
		}
		return base64SecretHandler(data)
	})

	createSecret(t, client, "wrapped", "base64-key", map[string][]byte{
		"a": []byte("a2V5IGE="), // "key a"
		"b": []byte("a2V5IGI="), // "key b"
	})
	createSecret(t, client, "other", "base64-key", map[string][]byte{"k": []byte("a2V5IGM=")}) // "key c"
	createSecret(t, client, "plain", "key", map[string][]byte{"k": []byte("plain key")})
	ks.syncOnce()
	all := map[string]string{
		keyFile("wrapped", "a", "key a"):   "key a",
		keyFile("wrapped", "b", "key b"):   "key b",
		keyFile("other", "k", "key c"):     "key c",
		keyFile("plain", "k", "plain key"): "plain key",
	}
	expectFiles(t, dir, all)

	// While the handler fails the keys of existing secrets are kept, but
	// deleted secrets are still revoked.
	failHandler.Store(true)
	deleteSecret(t, client, "other")
	deleteSecret(t, client, "plain")
	ks.syncOnce()
	ks.syncOnce()
	kept := map[string]string{
		keyFile("wrapped", "a", "key a"): "key a",
		keyFile("wrapped", "b", "key b"): "key b",
	}
	expectFiles(t, dir, kept)

	// A restarted server keeps the keys from disk as well.
	ks2 := newTestServer(client, dir, 0600)
	ks2.AddSecretKeyHandler("base64-key", func(map[string][]byte) (map[string][]byte, error) {
		return nil, errors.New("unwrapping service unavailable")
	})
	ks2.syncOnce()
	expectFiles(t, dir, kept)

	// Once the handler recovers, an updated secret replaces the old keys.
	failHandler.Store(false)
	updateSecret(t, client, "wrapped", "base64-key", map[string][]byte{"a": []byte("bmV3IGtleQ==")}) // "new key"
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("wrapped", "a", "new key"): "new key",
	})

	// And a deleted one is removed.
	deleteSecret(t, client, "wrapped")
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{})
}

// TestKeySyncRemovesKeysOnPermanentHandlerError checks that the keys of a
// secret are removed if its handler fails permanently, e.g. because access
// was revoked in the unwrapping service, while transient failures of other
// secrets still keep their keys.
func TestKeySyncRemovesKeysOnPermanentHandlerError(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()

	var revoked, unavailable atomic.Bool
	ks := newTestServer(client, dir, 0600)
	ks.AddSecretKeyHandler("base64-key", func(data map[string][]byte) (map[string][]byte, error) {
		switch {
		case revoked.Load() && string(data["revocable"]) == "true":
			return nil, sechandlers.NewPermanentError(errors.New("access denied"))
		case unavailable.Load():
			return nil, errors.New("unwrapping service unavailable")
		}
		delete(data, "revocable")
		return base64SecretHandler(data)
	})

	createSecret(t, client, "revoked", "base64-key", map[string][]byte{
		"a":         []byte("a2V5IGE="), // "key a"
		"revocable": []byte("true"),
	})
	createSecret(t, client, "unavailable", "base64-key", map[string][]byte{"k": []byte("a2V5IGM=")}) // "key c"
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("revoked", "a", "key a"):     "key a",
		keyFile("unavailable", "k", "key c"): "key c",
	})

	revoked.Store(true)
	unavailable.Store(true)
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("unavailable", "k", "key c"): "key c",
	})

	// The keys are synced again once access is restored.
	revoked.Store(false)
	unavailable.Store(false)
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("revoked", "a", "key a"):     "key a",
		keyFile("unavailable", "k", "key c"): "key c",
	})
}

// TestExistingKeyFiles checks which files are attributed to a secret when its
// handler fails.
func TestExistingKeyFiles(t *testing.T) {
	dir := t.TempDir()
	ks := newTestServer(newTestClient(), dir, 0600)

	want := []string{
		keyFile("foo", "k", "1"),
		keyFile("foo", "k-2", "2"),
		keyFile("foo", "k_3", "3"),        // entries may contain the separator
		keyFile("foo", "bar_k", "4"),      // and look like a secret name
		keyFile("foo", "-bar-k.pem", "5"), // or dashes
	}
	others := []string{
		keyFile("foo-bar", "k", "6"), // another secret starting with foo
		keyFile("foo.bar", "k", "7"),
		keyFile("fo", "k", "8"),
		keyFile("fo", "o_k", "9"),
		keyFile("bar", "k", "10"),
		getLocalKeyFilename("other-ns", "foo", "k", strings.Repeat("0", keyFileHashLen)),
		getLocalKeyFilename(testNamespace+"-foo", "k", "x", strings.Repeat("0", keyFileHashLen)),
		legacyKeyFile("foo", "k", "11"), // ambiguous, never kept
		"my_default_foo_key",
	}
	for _, name := range append(append([]string{}, want...), others...) {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}

	got := map[string]bool{}
	for _, f := range ks.existingKeyFiles(testNamespace, "foo") {
		got[f] = true
	}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for _, f := range want {
		if !got[f] {
			t.Fatalf("expected %q in %v", f, got)
		}
	}

	if got := ks.existingKeyFiles(testNamespace, "missing"); len(got) != 0 {
		t.Fatalf("expected no files, got %v", got)
	}

	ks.keySyncDir = filepath.Join(dir, "does-not-exist")
	if got := ks.existingKeyFiles(testNamespace, "foo"); len(got) != 0 {
		t.Fatalf("expected no files, got %v", got)
	}
}

// TestKeySyncNameOverlap checks that the keys of a deleted or revoked secret
// are removed although a secret whose name is a prefix of its name fails
// transiently and keeps its own keys.
func TestKeySyncNameOverlap(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()

	var failing atomic.Bool
	ks := newTestServer(client, dir, 0600)
	ks.AddSecretKeyHandler("base64-key", func(data map[string][]byte) (map[string][]byte, error) {
		if failing.Load() {
			if string(data["revoked"]) == "true" {
				return nil, sechandlers.NewPermanentError(errors.New("access denied"))
			}
			return nil, errors.New("unwrapping service unavailable")
		}
		delete(data, "revoked")
		return base64SecretHandler(data)
	})

	// The entries of foo-bar would be entries "bar-k" of foo in the legacy
	// format.
	createSecret(t, client, "foo", "base64-key", map[string][]byte{"k": []byte("a2V5IGE=")})     // "key a"
	createSecret(t, client, "foo-bar", "base64-key", map[string][]byte{"k": []byte("a2V5IGI=")}) // "key b"
	createSecret(t, client, "foo-baz", "base64-key", map[string][]byte{"k": []byte("a2V5IGM="),  // "key c"
		"revoked": []byte("true")})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("foo", "k", "key a"):     "key a",
		keyFile("foo-bar", "k", "key b"): "key b",
		keyFile("foo-baz", "k", "key c"): "key c",
	})

	failing.Store(true)
	deleteSecret(t, client, "foo-bar")
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("foo", "k", "key a"): "key a",
	})
}

// TestKeySyncLegacyKeyFiles checks that key files in the format of previous
// versions are replaced by the current format, and never kept for a failing
// secret since the secret they belong to is ambiguous.
func TestKeySyncLegacyKeyFiles(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()

	ks := newTestServer(client, dir, 0600)
	ks.AddSecretKeyHandler("base64-key", func(map[string][]byte) (map[string][]byte, error) {
		return nil, errors.New("unwrapping service unavailable")
	})

	createSecret(t, client, "plain", "key", map[string][]byte{"k": []byte("plain key")})
	createSecret(t, client, "wrapped", "base64-key", map[string][]byte{"k": []byte("a2V5IGE=")}) // "key a"
	for name, content := range map[string]string{
		legacyKeyFile("plain", "k", "plain key"): "plain key",
		legacyKeyFile("wrapped", "k", "key a"):   "key a",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("plain", "k", "plain key"): "plain key",
	})
}

// TestKeySyncSkipsInvalidNames checks that secrets whose namespace or name
// contain the key file name separator are not synced, as their key files
// could be attributed to another secret. The API server rejects such names.
func TestKeySyncSkipsInvalidNames(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)

	createSecret(t, client, "foo_bar", "key", map[string][]byte{"k": []byte("invalid")})
	createSecret(t, client, "valid", "key", map[string][]byte{"k": []byte("valid")})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("valid", "k", "valid"): "valid",
	})

	got := ks.syncSecretsToLocalKeys(&corev1.SecretList{Items: []corev1.Secret{{
		ObjectMeta: metav1.ObjectMeta{Name: "foo", Namespace: "my_ns"},
		Data:       map[string][]byte{"k": []byte("invalid")},
	}}}, sechandlers.RegularKeyHandler)
	if len(got) != 0 {
		t.Fatalf("expected no key files, got %v", got)
	}
	expectFiles(t, dir, map[string]string{
		keyFile("valid", "k", "valid"): "valid",
	})
}

// TestStartSyncsImmediately checks that the first sync does not wait for the
// interval.
func TestStartSyncsImmediately(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600) // interval of one hour
	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})

	// Start never returns, the goroutine is left waiting for the interval.
	go func() { _ = ks.Start() }()

	path := filepath.Join(dir, keyFile("my-secret", "mykey", "this is a key"))
	deadline := time.Now().Add(10 * time.Second)
	for !fileExists(path) {
		if time.Now().After(deadline) {
			t.Fatal("key was not synced on start")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestKeySyncHandlerError checks that a secret the handler cannot process is
// skipped without affecting other secrets.
func TestKeySyncHandlerError(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)
	ks.AddSecretKeyHandler("base64-key", base64SecretHandler)

	createSecret(t, client, "bad", "base64-key", map[string][]byte{"k": []byte("not base64!")})
	createSecret(t, client, "good", "base64-key", map[string][]byte{"k": []byte("Z29vZA==")}) // "good"
	ks.syncOnce()

	expectFiles(t, dir, map[string]string{
		keyFile("good", "k", "good"): "good",
	})
}

func TestKeySyncAddHandlersBeforeStart(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)
	ks.AddSecretKeyHandler("base64-key", base64SecretHandler)

	createSecret(t, client, "my-secret", "base64-key", map[string][]byte{
		"mykey": []byte("dGhpcyBpcyBhIGtleQ=="), // base64 of "this is a key"
	})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})

	deleteSecret(t, client, "my-secret")
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{})
}

func TestKeySyncAddHandlersAfterStart(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)

	createSecret(t, client, "my-secret", "base64-key", map[string][]byte{
		"mykey": []byte("dGhpcyBpcyBhIGtleQ=="), // base64 of "this is a key"
	})

	// Without a handler for the type, nothing is synced.
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{})

	// The handler takes effect on the next sync.
	ks.AddSecretKeyHandler("base64-key", base64SecretHandler)
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})

	deleteSecret(t, client, "my-secret")
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{})
}

// TestKeySyncReplaceHandler checks that adding a handler for an existing
// type replaces it, including the built-in "key" handler.
func TestKeySyncReplaceHandler(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("dGhpcyBpcyBhIGtleQ==")})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "dGhpcyBpcyBhIGtleQ=="): "dGhpcyBpcyBhIGtleQ==",
	})

	ks.AddSecretKeyHandler("key", base64SecretHandler)
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})
}

// TestKeySyncFilePermissions checks that key files get exactly the configured
// permissions, even when the umask would strip some of them.
func TestKeySyncFilePermissions(t *testing.T) {
	// A restrictive umask makes os.WriteFile produce different permissions
	// than requested for most cases below, exercising the chmod path.
	oldMask := syscall.Umask(0077)
	t.Cleanup(func() { syscall.Umask(oldMask) })

	for _, perm := range []os.FileMode{0600, 0400, 0640, 0644} {
		t.Run(perm.String(), func(t *testing.T) {
			dir := t.TempDir()
			client := newTestClient()
			ks := newTestServer(client, dir, perm)

			createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
			ks.syncOnce()

			fi, err := os.Stat(filepath.Join(dir, keyFile("my-secret", "mykey", "this is a key")))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != perm {
				t.Fatalf("expected permissions %v, got %v", perm, fi.Mode().Perm())
			}
		})
	}
}

// TestKeySyncFileOwner checks that setting the owner to the current user and
// group succeeds without needing CAP_CHOWN.
func TestKeySyncFileOwner(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	uid, gid := os.Getuid(), os.Getgid()
	ks := NewKeySyncServer(KeySyncServerConfig{
		K8sClient:          client,
		Interval:           time.Hour,
		KeySyncDir:         dir,
		Namespace:          testNamespace,
		KeyFilePermissions: 0600,
		KeyFileOwnerUID:    &uid,
		KeyFileOwnerGID:    &gid,
	})

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()

	fi, err := os.Stat(filepath.Join(dir, keyFile("my-secret", "mykey", "this is a key")))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Uid) != uid || int(st.Gid) != gid {
		t.Fatalf("expected owner %d:%d, got %d:%d", uid, gid, st.Uid, st.Gid)
	}
}

// supplementaryGroup returns a group the current user belongs to other than
// the one new files in dir get, so the file group can be changed without
// CAP_CHOWN.
func supplementaryGroup(t *testing.T, dir string) int {
	t.Helper()
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, nil, 0600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	defaultGID := int(fi.Sys().(*syscall.Stat_t).Gid)

	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g != defaultGID {
			return g
		}
	}
	t.Skip("current user has no supplementary group to change the file group to")
	return 0
}

// TestKeySyncFileOwnerOnlyGID checks that configuring only the group (or
// only the user) changes just that and leaves the other one untouched,
// instead of dereferencing the unset one.
func TestKeySyncFileOwnerOnlyGID(t *testing.T) {
	dir := t.TempDir()
	gid := supplementaryGroup(t, dir)
	client := newTestClient()
	ks := NewKeySyncServer(KeySyncServerConfig{
		K8sClient:          client,
		Interval:           time.Hour,
		KeySyncDir:         dir,
		Namespace:          testNamespace,
		KeyFilePermissions: 0600,
		KeyFileOwnerGID:    &gid,
	})

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()

	fi, err := os.Stat(filepath.Join(dir, keyFile("my-secret", "mykey", "this is a key")))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if int(st.Uid) != os.Getuid() || int(st.Gid) != gid {
		t.Fatalf("expected owner %d:%d, got %d:%d", os.Getuid(), gid, st.Uid, st.Gid)
	}
}

// TestKeySyncFileOwnerError checks that a key file whose ownership cannot be
// set is not left behind with the wrong owner. Otherwise later syncs would
// see the file as existing and never retry.
func TestKeySyncFileOwnerError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chown to any group")
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	member := map[int]bool{os.Getgid(): true}
	for _, g := range groups {
		member[g] = true
	}
	foreignGID := 0
	for member[foreignGID] {
		foreignGID++
	}

	dir := t.TempDir()
	client := newTestClient()
	ks := NewKeySyncServer(KeySyncServerConfig{
		K8sClient:          client,
		Interval:           time.Hour,
		KeySyncDir:         dir,
		Namespace:          testNamespace,
		KeyFilePermissions: 0600,
		KeyFileOwnerGID:    &foreignGID,
	})

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{})

	// Once ownership can be set, the next sync writes the key.
	gid := os.Getgid()
	ks.keyFileOwnerGID = &gid
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})
}

// TestKeySyncKeepsKeysWhenListFails checks that an error listing secrets does
// not purge already-synced keys from disk, which would break image pulls
// until the API server is reachable again.
func TestKeySyncKeepsKeysWhenListFails(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()

	var failList atomic.Bool
	client.PrependReactor("list", "secrets", func(coretesting.Action) (bool, runtime.Object, error) {
		if failList.Load() {
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	ks := newTestServer(client, dir, 0600)

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()
	synced := map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	}
	expectFiles(t, dir, synced)

	// The secret is deleted while the API server is unreachable: the key is
	// kept since we cannot tell whether it is still valid.
	deleteSecret(t, client, "my-secret")
	failList.Store(true)
	ks.syncOnce()
	expectFiles(t, dir, synced)

	// Once the API server is reachable again, the stale key is removed.
	failList.Store(false)
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{})
}

// TestKeySyncListError checks that a failing list for one type does not stop
// other types from being synced.
func TestKeySyncListError(t *testing.T) {
	dir := t.TempDir()
	client := newTestClient()
	client.PrependReactor("list", "secrets", func(action coretesting.Action) (bool, runtime.Object, error) {
		if action.(coretesting.ListAction).GetListRestrictions().Fields.String() == "type=base64-key" {
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	ks := newTestServer(client, dir, 0600)
	ks.AddSecretKeyHandler("base64-key", base64SecretHandler)

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()

	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})
}

func TestCombineFilenameMap(t *testing.T) {
	got := combineFilenameMap(map[string]bool{}, map[string]bool{"a": true})
	if len(got) != 1 || !got["a"] {
		t.Fatalf("unexpected result %v", got)
	}

	got = combineFilenameMap(map[string]bool{"a": true}, map[string]bool{"b": true})
	if len(got) != 2 || !got["a"] || !got["b"] {
		t.Fatalf("unexpected result %v", got)
	}
}

// skipIfRoot skips tests relying on permission errors, which root bypasses.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
}

// TestKeySyncUnwritableDir checks that a key that cannot be written is
// retried on the next sync, and that stale keys which cannot be deleted do
// not stop the sync.
func TestKeySyncUnwritableDir(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	client := newTestClient()

	stale := filepath.Join(dir, staleKeyFile)
	if err := os.WriteFile(stale, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	ks := newTestServer(client, dir, 0600)
	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{staleKeyFile: "old"})

	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})
}

// TestKeySyncMissingDir checks that a missing sync directory is reported
// without crashing, and syncing works once it exists.
func TestKeySyncMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	client := newTestClient()
	ks := newTestServer(client, dir, 0600)

	createSecret(t, client, "my-secret", "key", map[string][]byte{"mykey": []byte("this is a key")})
	ks.syncOnce()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("expected the sync directory not to be created, got %v", err)
	}

	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ks.syncOnce()
	expectFiles(t, dir, map[string]string{
		keyFile("my-secret", "mykey", "this is a key"): "this is a key",
	})
}

// TestSyncSecretsToLocalKeysDefaultNamespace checks that secrets without a
// namespace are stored under the default namespace.
func TestSyncSecretsToLocalKeysDefaultNamespace(t *testing.T) {
	dir := t.TempDir()
	ks := newTestServer(newTestClient(), dir, 0600)

	got := ks.syncSecretsToLocalKeys(&corev1.SecretList{Items: []corev1.Secret{{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret"},
		Data:       map[string][]byte{"mykey": []byte("this is a key")},
	}}}, sechandlers.RegularKeyHandler)

	want := keyFile("my-secret", "mykey", "this is a key")
	if len(got) != 1 || !got[want] {
		t.Fatalf("expected filename map {%s: true}, got %v", want, got)
	}
	expectFiles(t, dir, map[string]string{want: "this is a key"})
}
