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

package keysync

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestKeySync runs through syncing of a key for creation and deletion of a key
func TestKeySync(t *testing.T) {
	// Setup
	tmpDir, err := os.MkdirTemp("", "keysync")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.RemoveAll(tmpDir) // clean up
		if err != nil {
			t.Fatal(err)
		}
	}()

	var (
		fakeClient = fake.NewSimpleClientset()
		namespace  = "default"
		interval   = 5 * time.Second
	)

	ksc := KeySyncServerConfig{
		K8sClient:          fakeClient,
		Interval:           interval,
		KeySyncDir:         tmpDir,
		Namespace:          namespace,
		KeyFilePermissions: os.FileMode(0600),
		KeyFileOwnerUID:    nil,
		KeyFileOwnerGID:    nil,
	}
	kss := NewKeySyncServer(ksc)

	var kssErr error
	go func() { kssErr = kss.Start() }()

	// Ensure no keys at start
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) > 0 {
		t.Fatal("Should not have any files at this point")
	}

	// Create 1 key and check if exists
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret",
		},
		Data: map[string][]byte{
			"mykey": []byte("this is a key"),
		},
		Type: "key",
	}

	fmt.Println("Creating sample key")
	_, err = fakeClient.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Unable to create secret: %v", err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 {
		t.Fatal("Should have 1 file at this point")
	}

	fmt.Println("Filepath: ", filepath.Join(tmpDir, files[0].Name()))
	contents, err := os.ReadFile(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != string(secret.Data["mykey"]) {
		t.Fatalf("Key string differs, expected %v, got %v",
			string(secret.Data["mykey"]), string(contents))
	}

	// Delete secret and check if it is removed
	err = fakeClient.CoreV1().Secrets(namespace).Delete(context.Background(), secret.GetName(), metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) > 0 {
		t.Fatal("Should not have any files after deletion")
	}

	if kssErr != nil {
		t.Fatalf("KeySyncServer errored: %v", kssErr)
	}
}

// TestKeySyncAddHandlersBeforeStart runs through syncing of a key for creation and deletion of a key
// with special secret handlers before server start
func TestKeySyncAddHandlersBeforeStart(t *testing.T) {
	// Setup
	tmpDir, err := os.MkdirTemp("", "keysync")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.RemoveAll(tmpDir) // clean up
		if err != nil {
			t.Fatal(err)
		}
	}()

	var (
		fakeClient = fake.NewSimpleClientset()
		namespace  = "default"
		interval   = 5 * time.Second
	)

	// Due to limitation of fakeclient not implementing server side field selector
	// https://github.com/kubernetes/kubernetes/issues/78824
	// Therefore, this is a quick hack to prevent a list with type=key to return
	// the base64-key.
	// TODO: https://github.com/IBM/k8s-enc-image-operator/issues/14
	// Create a more generic framework for fakeclient to implement field
	// selectors on secrets
	fakeClient.PrependReactor("list", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		switch la := action.(type) {
		case coretesting.ListAction:
			if la.GetListRestrictions().Fields.String() == "type=key" {
				return true, &corev1.SecretList{
					Items: []corev1.Secret{},
				}, nil
			}
		}
		return false, nil, nil
	})

	base64SecretHandler := func(data map[string][]byte) (map[string][]byte, error) {
		retmap := map[string][]byte{}
		for k, v := range data {
			s, err := base64.StdEncoding.DecodeString(string(v))
			if err != nil {
				return nil, err
			}
			retmap[k] = []byte(s)
		}
		return retmap, nil
	}

	ksc := KeySyncServerConfig{
		K8sClient:          fakeClient,
		Interval:           interval,
		KeySyncDir:         tmpDir,
		Namespace:          namespace,
		KeyFilePermissions: os.FileMode(0600),
		KeyFileOwnerUID:    nil,
		KeyFileOwnerGID:    nil,
	}

	kss := NewKeySyncServer(ksc)

	// Add new secret key handler
	kss.AddSecretKeyHandler("base64-key", base64SecretHandler)

	var kssErr error
	go func() { kssErr = kss.Start() }()

	// Ensure no keys at start
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) > 0 {
		t.Fatal("Should not have any files at this point")
	}

	// Create 1 key and check if exists
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret",
		},
		Data: map[string][]byte{
			"mykey": []byte("dGhpcyBpcyBhIGtleQ=="), //  base64 of "this is a key"
		},
		Type: "base64-key",
	}

	fmt.Println("Creating sample key")
	_, err = fakeClient.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Unable to create secret: %v", err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 {
		t.Fatalf("Should have 1 file at this point, have %v", len(files))
	}

	fmt.Println("Filepath: ", filepath.Join(tmpDir, files[0].Name()))
	contents, err := os.ReadFile(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "this is a key" {
		t.Fatalf("Key string differs, expected %v, got %v",
			string("this is a key"), string(contents))
	}

	// Delete secret and check if it is removed
	err = fakeClient.CoreV1().Secrets(namespace).Delete(context.Background(), secret.GetName(), metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) > 0 {
		t.Fatal("Should not have any files after deletion")
	}

	if kssErr != nil {
		t.Fatalf("KeySyncServer errored: %v", kssErr)
	}
}

// TestKeySyncAddHandlersAfterStart runs through syncing of a key for creation and deletion of a key
// with special secret handlers after server start
func TestKeySyncAddHandlersAfterStart(t *testing.T) {
	// Setup
	tmpDir, err := os.MkdirTemp("", "keysync")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err = os.RemoveAll(tmpDir) // clean up
		if err != nil {
			t.Fatal(err)
		}
	}()

	var (
		fakeClient = fake.NewSimpleClientset()
		namespace  = "default"
		interval   = 5 * time.Second
	)

	// Due to limitation of fakeclient not implementing server side field selector
	// https://github.com/kubernetes/kubernetes/issues/78824
	// Therefore, this is a quick hack to prevent a list with type=key to return
	// the base64-key.
	// TODO: https://github.com/IBM/k8s-enc-image-operator/issues/14
	// Create a more generic framework for fakeclient to implement field
	// selectors on secrets
	fakeClient.PrependReactor("list", "secrets", func(action coretesting.Action) (handled bool, ret runtime.Object, err error) {
		switch la := action.(type) {
		case coretesting.ListAction:
			if la.GetListRestrictions().Fields.String() == "type=key" {
				return true, &corev1.SecretList{
					Items: []corev1.Secret{},
				}, nil
			}
		}
		return false, nil, nil
	})

	base64SecretHandler := func(data map[string][]byte) (map[string][]byte, error) {
		retmap := map[string][]byte{}
		for k, v := range data {
			s, err := base64.StdEncoding.DecodeString(string(v))
			if err != nil {
				return nil, err
			}
			retmap[k] = []byte(s)
		}
		return retmap, nil
	}

	ksc := KeySyncServerConfig{
		K8sClient:          fakeClient,
		Interval:           interval,
		KeySyncDir:         tmpDir,
		Namespace:          namespace,
		KeyFilePermissions: os.FileMode(0600),
		KeyFileOwnerUID:    nil,
		KeyFileOwnerGID:    nil,
	}

	kss := NewKeySyncServer(ksc)
	var kssErr error
	go func() { kssErr = kss.Start() }()

	// Ensure no keys at start
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) > 0 {
		t.Fatal("Should not have any files at this point")
	}

	// Create 1 key and check if exists
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret",
		},
		Data: map[string][]byte{
			"mykey": []byte("dGhpcyBpcyBhIGtleQ=="), //  base64 of "this is a key"
		},
		Type: "base64-key",
	}

	fmt.Println("Creating sample key")
	_, err = fakeClient.CoreV1().Secrets(namespace).Create(context.Background(), secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Unable to create secret: %v", err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// Should not handle base64 keys since we didnt add the handler
	if len(files) != 0 {
		t.Fatalf("Should have 0 file at this point, have %v", len(files))
	}

	// Add new secret key handler and test again, and it should now have a key
	kss.AddSecretKeyHandler("base64-key", base64SecretHandler)

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 {
		t.Fatalf("Should have 1 file at this point, have %v", len(files))
	}

	fmt.Println("Filepath: ", filepath.Join(tmpDir, files[0].Name()))
	contents, err := os.ReadFile(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "this is a key" {
		t.Fatalf("Key string differs, expected %v, got %v",
			string("this is a key"), string(contents))
	}

	// Delete secret and check if it is removed
	err = fakeClient.CoreV1().Secrets(namespace).Delete(context.Background(), secret.GetName(), metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) > 0 {
		t.Fatal("Should not have any files after deletion")
	}

	if kssErr != nil {
		t.Fatalf("KeySyncServer errored: %v", kssErr)
	}
}
