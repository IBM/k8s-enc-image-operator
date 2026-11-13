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

	stale := filepath.Join(dir, "0123-default-old-secret-key")
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

	stale := filepath.Join(dir, "0123-default-old-secret-key")
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
	expectFiles(t, dir, map[string]string{"0123-default-old-secret-key": "old"})

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
