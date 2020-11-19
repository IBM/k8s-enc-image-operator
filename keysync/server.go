package keysync

import (
	"crypto/md5" // #nosec G501
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
)

const (
	keyTypeFieldSelectorPrefix = "type="
)

// KeySyncServer contains the parameters required for operation of the
// key sync server
type KeySyncServer struct {
	// K8sClient is the k8s clientset to interface with the kubernetes
	// cluster
	K8sClient clientset.Interface

	// Interval is the query interval in which to sync the decryption keys
	Interval time.Duration

	// KeySyncDir specifies the directory where keys are synced to
	KeySyncDir string

	// Namespace specifies the namespace where key secrets are stored
	Namespace string

	// SpecialKeyHandlers handles non-standard keys with additional requirements
	// such as requiring a remote unwrapping service, or talking to a HSM, etc.
	// The map contains a mapping of key type of the secret that it handles,
	// i.e. "kp-key" would be a map to secrets with "type=kp-key"
	// to a handler of how the secret data will be translated to the key file.
	SpecialKeyHandlers map[string]sechandlers.SecretKeyHandler
}

// Start begins running the KeySyncServer according to the parameters
// specified
func (ks *KeySyncServer) Start() error {
	secClient := ks.K8sClient.CoreV1().Secrets(ks.Namespace)

	if ks.SpecialKeyHandlers == nil {
		ks.SpecialKeyHandlers = map[string]sechandlers.SecretKeyHandler{}
	}
	// add the regular key type to the list of special key handlers
	ks.SpecialKeyHandlers["key"] = sechandlers.RegularKeyHandler

	// Create channel for immediate call for the first time
	for {
		<-time.After(ks.Interval)

		// Get list of new keys so that we can clean up obselete keys for revocation reasons
		allFilenameMap := map[string]bool{}

		for secType, skh := range ks.SpecialKeyHandlers {
			secList, err := secClient.List(metav1.ListOptions{
				FieldSelector: keyTypeFieldSelectorPrefix + secType,
			})
			if err != nil {
				logrus.Errorf("Error listing secrets: %v", err)
				continue
			}
			filenameMap := ks.syncSecretsToLocalKeys(secList, skh)

			allFilenameMap = combineFilenameMap(allFilenameMap, filenameMap)
		}

		// Purge keys which are not new
		ks.cleanupKeys(allFilenameMap)
	}
}

// combineFilenameMap returns a map that combines the contents of both f1 and f2
// is potentially destructive to f1 for optimization reasons (like slice appends)
func combineFilenameMap(f1 map[string]bool, f2 map[string]bool) map[string]bool {
	if len(f1) == 0 {
		return f2
	}

	for k, b := range f2 {
		f1[k] = b
	}

	return f1
}

// syncSecretsToLocalKeys syncs the secrets to the local keys, errors are logged
// and syncing is done on a best effort basis and returns the list of filenames
// that were written
func (ks *KeySyncServer) syncSecretsToLocalKeys(secList *corev1.SecretList, skh sechandlers.SecretKeyHandler) map[string]bool {
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

		// Process the secrets to filename/priv key map
		keyFiles, err := skh(s.Data)
		if err != nil {
			logrus.Errorf("Unable to process secret %s: %v", name, err)
			continue
		}

		// For each file in the secret
		for filename, data := range keyFiles {
			hashString := fmt.Sprintf("%x", md5.Sum(data)) // #nosec G401

			// Hash contents of each file, and check if they exists
			// already before writing
			filename := getLocalKeyFilename(namespace, name, filename, hashString)

			// keep track of list of hashes for cleanup
			filenameMap[filename] = true

			// Write file to directory if file doesn't already exist
			path := filepath.Join(ks.KeySyncDir, filename)
			if !fileExists(path) {
				logrus.Printf("Syncing new key: %v", filename)
				err := ioutil.WriteFile(path, data, 0600)
				if err != nil {
					logrus.Errorf("Unable to write file %s", path)
					continue
				}
			}
		}
	}
	return filenameMap
}

func (ks *KeySyncServer) cleanupKeys(filenameMap map[string]bool) {
	// Do cleanup of files that are not part of current secrets
	files, err := ioutil.ReadDir(ks.KeySyncDir)
	if err != nil {
		files = []os.FileInfo{}
		logrus.Errorf("Unable to list directory for cleanup")
	}

	// Remove all files that are not tracked based on filename map
	// from above
	for _, file := range files {
		filename := file.Name()
		if !filenameMap[filename] {
			path := filepath.Join(ks.KeySyncDir, filename)
			logrus.Printf("Deleting old key: %v", filename)
			if err = os.Remove(path); err != nil {
				logrus.Errorf("Unable to delete old key %v, %v", path, err)
			}
		}
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
