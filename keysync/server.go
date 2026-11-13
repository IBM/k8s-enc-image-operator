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
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
)

const (
	keyTypeFieldSelectorPrefix = "type="
)

// KeySyncServerConfig contains the parameters required for operation of the
// key sync server
type KeySyncServerConfig struct {
	// K8sClient is the k8s clientset to interface with the kubernetes
	// cluster
	K8sClient clientset.Interface

	// Interval is the query interval in which to sync the decryption keys
	Interval time.Duration

	// KeySyncDir specifies the directory where keys are synced to
	KeySyncDir string

	// Namespace specifies the namespace where key secrets are stored
	Namespace string

	// KeyFilePermissions specifies the permissions to set on the created files
	KeyFilePermissions os.FileMode

	// KeyFileOwnerUID specifies the owner UID to set on the created files
	// if nil, owner UID won't be changed, therefore files will be created with process UID
	KeyFileOwnerUID *int

	// KeyFileOwnerGID specifies the owner GID to set on the created files
	// if nil, owner GID won't be changed, therefore files will be created with process GID
	KeyFileOwnerGID *int
}

// KeySyncServer represents the server to perform key syncing
type KeySyncServer struct {
	// k8sClient is the k8s clientset to interface with the kubernetes
	// cluster
	k8sClient clientset.Interface

	// interval is the query interval in which to sync the decryption keys
	interval time.Duration

	// keySyncDir specifies the directory where keys are synced to
	keySyncDir string

	// namespace specifies the namespace where key secrets are stored
	namespace string

	// keyFilePermissions specifies the permissions to set on the created files
	keyFilePermissions os.FileMode

	// keyFileOwnerUID specifies the owner UID to set on the created files
	// if nil, owner UID won't be changed, therefore files will be created with process UID
	keyFileOwnerUID *int

	// keyFileOwnerGID specifies the owner GID to set on the created files
	// if nil, owner GID won't be changed, therefore files will be created with process GID
	keyFileOwnerGID *int

	// keyHandlers handles non-standard keys with additional requirements
	// such as requiring a remote unwrapping service, or talking to a HSM, etc.
	// The map contains a mapping of key type of the secret that it handles,
	// i.e. "kp-key" would be a map to secrets with "type=kp-key"
	// to a handler of how the secret data will be translated to the key file.
	keyHandlers map[string]sechandlers.SecretKeyHandler

	// addKeyHandlers is a workspace map for adding new key handlers, we use
	// a separate map since it introduces concurrency, and so we want to minimize
	// locking to the addKeyHandler map instead of the main one
	addKeyHandlers map[string]sechandlers.SecretKeyHandler

	// addKeyHandlersMutex to handle concurrency for addKeyHandlers
	addKeyHandlersMutex *sync.Mutex
}

func NewKeySyncServer(ksc KeySyncServerConfig) *KeySyncServer {
	ks := KeySyncServer{
		k8sClient:           ksc.K8sClient,
		interval:            ksc.Interval,
		keySyncDir:          ksc.KeySyncDir,
		namespace:           ksc.Namespace,
		keyHandlers:         map[string]sechandlers.SecretKeyHandler{},
		addKeyHandlers:      map[string]sechandlers.SecretKeyHandler{},
		addKeyHandlersMutex: &sync.Mutex{},
		keyFilePermissions:  ksc.KeyFilePermissions,
		keyFileOwnerUID:     ksc.KeyFileOwnerUID,
		keyFileOwnerGID:     ksc.KeyFileOwnerGID,
	}

	// add the regular key type to the list of special key handlers
	ks.keyHandlers["key"] = sechandlers.RegularKeyHandler

	return &ks
}

// Start begins running the KeySyncServer according to the parameters
// specified.
// Only one instance of Start should be run per KeySyncServer
func (ks *KeySyncServer) Start() error {
	for {
		<-time.After(ks.interval)
		ks.syncOnce()
	}
}

// syncOnce performs a single sync of all secrets to local key files and
// removes key files whose secrets no longer exist.
func (ks *KeySyncServer) syncOnce() {
	secClient := ks.k8sClient.CoreV1().Secrets(ks.namespace)

	// Check if new handlers to add
	ks.addKeyHandlersMutex.Lock()
	for k, v := range ks.addKeyHandlers {
		ks.keyHandlers[k] = v
	}
	ks.addKeyHandlers = map[string]sechandlers.SecretKeyHandler{}
	ks.addKeyHandlersMutex.Unlock()

	// Get list of new keys so that we can clean up obselete keys for revocation reasons
	allFilenameMap := map[string]bool{}
	listFailed := false

	for secType, skh := range ks.keyHandlers {
		secList, err := secClient.List(context.Background(), metav1.ListOptions{
			FieldSelector: keyTypeFieldSelectorPrefix + secType,
		})
		if err != nil {
			slog.Error("Error listing secrets", "secretType", secType, "error", err)
			listFailed = true
			continue
		}
		filenameMap := ks.syncSecretsToLocalKeys(secList, skh)

		allFilenameMap = combineFilenameMap(allFilenameMap, filenameMap)
	}

	// If any list failed we do not know which keys are still valid, so skip
	// the cleanup instead of deleting every key of the failed type from disk
	// (which would break image pulls until the API is reachable again).
	if listFailed {
		slog.Warn("Skipping cleanup of old keys because listing secrets failed")
		return
	}

	// Purge keys which are not new
	ks.cleanupKeys(allFilenameMap)
}

// AddKeyHandler will queue adding new handlers to the key sync server that will
// take effect on the next sync.
// SecretKeyHandlers handles non-standard keys with additional requirements
// such as requiring a remote unwrapping service, or talking to a HSM, etc.
// The map contains a mapping of key type of the secret that it handles,
// i.e. "kp-key" would be a map to secrets with "type=kp-key"
// to a handler of how the secret data will be translated to the key file.
func (ks *KeySyncServer) AddSecretKeyHandler(secretType string, skh sechandlers.SecretKeyHandler) {
	ks.addKeyHandlersMutex.Lock()
	defer ks.addKeyHandlersMutex.Unlock()

	ks.addKeyHandlers[secretType] = skh
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

		namespace := s.GetNamespace()
		if namespace == "" {
			namespace = metav1.NamespaceDefault
		}

		name := s.GetName()

		// Process the secrets to filename/priv key map
		keyFiles, err := skh(s.Data)
		if err != nil {
			slog.Error("Unable to process secret", "secret", name, "error", err)
			continue
		}

		// For each file in the secret
		for filename, data := range keyFiles {
			hashString := fmt.Sprintf("%x", md5.Sum(data)) // #nosec G401 Needed only to check if file exists

			// Hash contents of each file, and check if they exists
			// already before writing
			filename := getLocalKeyFilename(namespace, name, filename, hashString)

			// keep track of list of hashes for cleanup
			filenameMap[filename] = true

			// Write file to directory if file doesn't already exist
			path := filepath.Join(ks.keySyncDir, filename)

			if !fileExists(path) {
				slog.Info("Syncing new key", "filename", filename)
				err := ks.writeKeyFile(path, data)
				if err != nil {
					slog.Error("Unable to write file", "path", path, "error", err)
					continue
				}
			}
		}
	}
	return filenameMap
}

func (ks *KeySyncServer) cleanupKeys(filenameMap map[string]bool) {
	// Do cleanup of files that are not part of current secrets
	files, err := os.ReadDir(ks.keySyncDir)
	if err != nil {
		files = []fs.DirEntry{}
		slog.Error("Unable to list directory for cleanup", "dir", ks.keySyncDir, "error", err)
	}

	// Remove all files that are not tracked based on filename map
	// from above
	for _, file := range files {
		filename := file.Name()
		if !filenameMap[filename] {
			path := filepath.Join(ks.keySyncDir, filename)
			slog.Info("Deleting old key", "filename", filename)
			if err = os.Remove(path); err != nil {
				slog.Error("Unable to delete old key", "path", path, "error", err)
			}
		}
	}
}

// writeKeyFile writes key into the specified file
// and makes sure that the file has the specified
// permissions and ownership. If that fails, the file is removed so that the
// next sync retries instead of treating the key as already synced.
func (ks *KeySyncServer) writeKeyFile(filepath string, data []byte) error {
	// Writing data into the specified file
	err := os.WriteFile(filepath, data, ks.keyFilePermissions)
	if err != nil {
		return err
	}

	if err := ks.setKeyFileAttributes(filepath); err != nil {
		if rmErr := os.Remove(filepath); rmErr != nil {
			slog.Error("Unable to remove key file", "path", filepath, "error", rmErr)
		}
		return err
	}

	return nil
}

// setKeyFileAttributes makes sure that the file has the configured
// permissions and ownership.
func (ks *KeySyncServer) setKeyFileAttributes(filepath string) error {
	// Getting information about the written file
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return err
	}

	// Permission configuration might be needed as WriteFile does not
	// guarantee the specified permissions due to umask
	if fileInfo.Mode() != ks.keyFilePermissions {
		err = os.Chmod(filepath, ks.keyFilePermissions)
		if err != nil {
			return err
		}
	}

	// Owner configuration when a specific uid and/or gid is configured.
	// -1 leaves the respective id unchanged. Changing the owner (or the group
	// to one the process is not a member of) requires CAP_CHOWN.
	stat := fileInfo.Sys().(*syscall.Stat_t)
	uid, gid := -1, -1
	// #nosec G115 userid and groupid should not be bigger then uint32
	if ks.keyFileOwnerUID != nil && stat.Uid != uint32(*ks.keyFileOwnerUID) {
		uid = *ks.keyFileOwnerUID
	}
	// #nosec G115 userid and groupid should not be bigger then uint32
	if ks.keyFileOwnerGID != nil && stat.Gid != uint32(*ks.keyFileOwnerGID) {
		gid = *ks.keyFileOwnerGID
	}
	if uid != -1 || gid != -1 {
		err = os.Chown(filepath, uid, gid)
		if err != nil {
			return err
		}
	}

	return nil
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
