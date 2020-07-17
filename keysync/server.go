package keysync

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	KeyTypeFieldSelector = "type=key"
)

// KeySyncServer contains the parameters required for operation of the
// key sync server
type KeySyncServer struct {
	// K8sClient is the k8s clientset to interface with the kubernetes
	// cluster
	K8sClient *kubernetes.Clientset

	// Interval is the query interval in which to sync the decryption keys
	Interval time.Duration

	// KeySyncDir specifies the directory where keys are synced to
	KeySyncDir string

	// Namespace specifies the namespace where key secrets are stored
	Namespace string
}

// Start begins running the KeySyncServer according to the parameters
// specified
func (ks *KeySyncServer) Start() error {
	secClient := ks.K8sClient.CoreV1().Secrets(ks.Namespace)

	// Create channel for immediate call for the first time
	for {
		select {
		case <-time.After(ks.Interval):
			secList, err := secClient.List(metav1.ListOptions{
				FieldSelector: "type=key",
			})
			if err != nil {
				logrus.Errorf("Error listing secrets: %v", err)
				continue
			}

			ks.syncSecretsToLocalKeys(secList)
		}
	}
	return nil
}

// syncSecretsToLocalKeys syncs the secrets to the local keys, errors are logged
// and syncing is done on a best effort basis
func (ks *KeySyncServer) syncSecretsToLocalKeys(secList *corev1.SecretList) {
	filenameMap := map[string]bool{}
	for _, s := range secList.Items {
		// Construct canonical secret filename based on hash
		// This way we can easily check if the file has changed,
		// and remove the rest that are not in the list of hashes

		namespace := s.ObjectMeta.Namespace
		if namespace == "" {
			namespace = metav1.NamespaceDefault
		}

		name := s.ObjectMeta.Name

		// For each file in the secret
		for filename, data := range s.Data {
			hashString := fmt.Sprintf("%x", md5.Sum(data))

			// Hash contents of each file, and check if they exists
			// already before writing
			filename := getLocalKeyFilename(namespace, name, filename, hashString)

			// keep track of list of hashes for cleanup
			filenameMap[filename] = true

			// Write file to directory if file doesn't already exist
			path := filepath.Join(ks.KeySyncDir, filename)
			if !fileExists(path) {
				err := ioutil.WriteFile(path, data, 0600)
				if err != nil {
					logrus.Errorf("Unable to write file %s", path)
					continue
				}
			}
		}

		// TODO: Do cleanup of files that are not part of current secrets
		// Get list of files in directory

		// Remove all files that are not tracked based on filename map
		// from above
	}
}

// getLocalKeyFilename returns the local filename to use, format is
// <md5>-namespace-secretName-filename
// i.e. a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447-default-mysecret-a.pem
func getLocalKeyFilename(namespace, name, filename, hashString string) string {
	return fmt.Sprintf("%s-%s-%s-%s", hashString, namespace, name, filename)
}

// fileExists returns true if the file exists
// errors from Stat are not handled, as this is a optimistic check, if a false
// negative results, it is still fine for our usecase
func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
}
