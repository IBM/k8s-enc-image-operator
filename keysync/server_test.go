package keysync

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	coretesting "k8s.io/client-go/testing"

	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestKeySync runs through syncing of a key for creation and deletion of a key
func TestKeySync(t *testing.T) {
	// Setup
	tmpDir, err := ioutil.TempDir("", "keysync")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir) // clean up

	var (
		fakeClient = fake.NewSimpleClientset()
		namespace  = "default"
		interval   = 5 * time.Second
	)

	kss := KeySyncServer{
		K8sClient:  fakeClient,
		Interval:   interval,
		KeySyncDir: tmpDir,
		Namespace:  namespace,
	}

	var kssErr error
	go func() { kssErr = kss.Start() }()

	// Ensure no keys at start
	files, err := ioutil.ReadDir(tmpDir)
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
	_, err = fakeClient.CoreV1().Secrets(namespace).Create(secret)
	if err != nil {
		t.Fatalf("Unable to create secret: %v", err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = ioutil.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 {
		t.Fatal("Should have 1 file at this point")
	}

	fmt.Println("Filepath: ", filepath.Join(tmpDir, files[0].Name()))
	contents, err := ioutil.ReadFile(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != string(secret.Data["mykey"]) {
		t.Fatalf("Key string differs, expected %v, got %v",
			string(secret.Data["mykey"]), string(contents))
	}

	// Delete secret and check if it is removed
	err = fakeClient.CoreV1().Secrets(namespace).Delete(secret.ObjectMeta.Name, &metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = ioutil.ReadDir(tmpDir)
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

// TestKeySyncSpecialSecretHandlers runs through syncing of a key for creation and deletion of a key
// with special secret handlers
func TestKeySyncSpecialSecretHandlers(t *testing.T) {
	// Setup
	tmpDir, err := ioutil.TempDir("", "keysync")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir) // clean up

	var (
		fakeClient = fake.NewSimpleClientset()
		namespace  = "default"
		interval   = 5 * time.Second
	)

	// Due to limitation of fakeclient not implementing server side field selector
	// https://github.com/kubernetes/kubernetes/issues/78824
	// Therefore, this is a quick hack to prevent a list with type=key to return
	// the base64-key.
	// TODO: Create a more generic framework for fakeclient to implement field
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

	kss := KeySyncServer{
		K8sClient:  fakeClient,
		Interval:   interval,
		KeySyncDir: tmpDir,
		Namespace:  namespace,
		SpecialKeyHandlers: map[string]sechandlers.SecretKeyHandler{
			"base64-key": base64SecretHandler,
		},
	}

	var kssErr error
	go func() { kssErr = kss.Start() }()

	// Ensure no keys at start
	files, err := ioutil.ReadDir(tmpDir)
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
	_, err = fakeClient.CoreV1().Secrets(namespace).Create(secret)
	if err != nil {
		t.Fatalf("Unable to create secret: %v", err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = ioutil.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	// fakeclient doesn't support filtering on calls so, the call to filter
	// only certain types
	if len(files) != 1 {
		t.Fatalf("Should have 1 file at this point, have %v", len(files))
	}

	fmt.Println("Filepath: ", filepath.Join(tmpDir, files[0].Name()))
	contents, err := ioutil.ReadFile(filepath.Join(tmpDir, files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "this is a key" {
		t.Fatalf("Key string differs, expected %v, got %v",
			string("this is a key"), string(contents))
	}

	// Delete secret and check if it is removed
	err = fakeClient.CoreV1().Secrets(namespace).Delete(secret.ObjectMeta.Name, &metav1.DeleteOptions{})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Sleeping 2x interval")
	time.Sleep(interval * 2)

	files, err = ioutil.ReadDir(tmpDir)
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
