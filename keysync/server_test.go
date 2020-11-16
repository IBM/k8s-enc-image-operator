package keysync

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

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
