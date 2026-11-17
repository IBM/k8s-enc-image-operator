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

// Package keysync implements the server syncing decryption keys from
// kubernetes secrets to local key files.
package keysync

import (
	"context"
	"crypto/md5" // #nosec G501 Usage is not related to security
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

	// keyFileHashLen is the length of the hex encoded hash that key file
	// names start with, see getLocalKeyFilename.
	keyFileHashLen = 2 * md5.Size

	// tempFilePrefix is the name prefix of the temporary files key files are
	// written to before being renamed into place.
	tempFilePrefix = ".keysync-tmp-"

	// keyFileSep separates the parts of key file names, see
	// getLocalKeyFilename. Namespace and secret names cannot contain it, so
	// the secret a key file was synced from is unambiguous.
	keyFileSep = "_"
)

var (
	// managedKeyFileRe matches the names of key files written by the server,
	// see getLocalKeyFilename. Only such files are removed during cleanup, so
	// that other files in the sync directory are left alone.
	managedKeyFileRe = regexp.MustCompile(fmt.Sprintf(`^[0-9a-f]{%d}%s.`, keyFileHashLen, keyFileSep))

	// legacyKeyFileRe matches the names of key files written by previous
	// versions, in the format <md5>-namespace-secretName-filename. As secret
	// and entry names may contain dashes, the secret such a file was synced
	// from is ambiguous. They are removed during cleanup and never kept for a
	// secret whose handler fails, since the files of another (deleted or
	// revoked) secret could be kept that way.
	legacyKeyFileRe = regexp.MustCompile(fmt.Sprintf(`^[0-9a-f]{%d}-.`, keyFileHashLen))
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

// NewKeySyncServer returns a key sync server with the given configuration,
// handling secrets of type "key". Start runs it.
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
// The first sync is done immediately, then once every interval.
func (ks *KeySyncServer) Start() error {
	for {
		ks.syncOnce()
		<-time.After(ks.interval)
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

		maps.Copy(allFilenameMap, filenameMap)
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

// AddSecretKeyHandler will queue adding new handlers to the key sync server that will
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

		// The API server does not allow the separator in namespace and secret
		// names. Should it appear anyway, the key files would be attributed
		// to the wrong secret, so the secret is not synced at all.
		if strings.Contains(namespace, keyFileSep) || strings.Contains(name, keyFileSep) {
			slog.Error("Unable to process secret, invalid namespace or name",
				"namespace", namespace, "secret", name)
			continue
		}

		// Process the secrets to filename/priv key map
		keyFiles, err := skh(s.Data)
		if err != nil {
			// A permanent error, e.g. access to the unwrapping service being
			// revoked, means the keys should no longer be on the node, so
			// they are removed by the cleanup.
			if sechandlers.IsPermanent(err) {
				slog.Error("Unable to process secret, removing its existing key files",
					"secret", name, "error", err)
				continue
			}

			// The secret still exists, so keep the key files synced from it
			// before. Otherwise a transient failure of the handler (e.g. an
			// unreachable unwrapping service) would remove the keys from
			// disk and break image pulls until it recovers.
			kept := ks.existingKeyFiles(namespace, name)
			slog.Error("Unable to process secret, keeping its existing key files",
				"secret", name, "error", err, "keptFiles", len(kept))
			for _, f := range kept {
				filenameMap[f] = true
			}
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

	// Remove all key files that are not tracked based on filename map
	// from above, as well as temporary files left behind by an interrupted
	// write. Other files are not touched, the sync directory might be shared
	// with keys not managed by us.
	for _, file := range files {
		filename := file.Name()
		if !file.Type().IsRegular() || filenameMap[filename] {
			continue
		}
		path := filepath.Join(ks.keySyncDir, filename)
		switch {
		case isManagedKeyFile(filename):
			slog.Info("Deleting old key", "filename", filename)
		case strings.HasPrefix(filename, tempFilePrefix):
			slog.Info("Deleting stale temporary file", "filename", filename)
		default:
			continue
		}
		if err = os.Remove(path); err != nil {
			slog.Error("Unable to delete file", "path", path, "error", err)
		}
	}
}

// existingKeyFiles returns the names of the key files in the sync directory
// that were synced from the given secret. Key files in the legacy format are
// not returned, see legacyKeyFileRe.
func (ks *KeySyncServer) existingKeyFiles(namespace, name string) []string {
	files, err := os.ReadDir(ks.keySyncDir)
	if err != nil {
		// Cleanup is not able to list the directory either, so nothing
		// gets removed.
		return nil
	}

	suffixPrefix := keyFileSep + namespace + keyFileSep + name + keyFileSep
	var existing []string
	for _, file := range files {
		filename := file.Name()
		if file.Type().IsRegular() && managedKeyFileRe.MatchString(filename) &&
			strings.HasPrefix(filename[keyFileHashLen:], suffixPrefix) {
			existing = append(existing, filename)
		}
	}
	return existing
}

// isManagedKeyFile returns true if filename is the name of a key file written
// by the server, in the current or the legacy format.
func isManagedKeyFile(filename string) bool {
	return managedKeyFileRe.MatchString(filename) || legacyKeyFileRe.MatchString(filename)
}

// writeKeyFile atomically writes key into the specified file with the
// configured permissions and ownership: the data is written to a temporary
// file in the same directory, which is renamed into place once complete.
// This way the container runtime never sees a partially written key, and an
// interrupted write does not leave a truncated key file behind that later
// syncs would treat as already synced.
func (ks *KeySyncServer) writeKeyFile(path string, data []byte) error {
	// CreateTemp creates the file with 0600 permissions, so the key is not
	// readable by others while being written.
	f, err := os.CreateTemp(filepath.Dir(path), tempFilePrefix+"*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	renamed := false
	defer func() {
		if renamed {
			return
		}
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			slog.Error("Unable to remove temporary file", "path", tmpPath, "error", err)
		}
	}()

	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}

	if err := ks.setKeyFileAttributes(tmpPath); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	renamed = true

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
// <md5>_namespace_secretName_filename
// i.e. 9e107d9d372bb6826bd81d3542a419d6_default_mysecret_a.pem
// Cleanup relies on this format (see managedKeyFileRe) to tell key files
// written by the server apart from other files in the sync directory.
// Namespace and secret names cannot contain underscores (unlike the filename,
// which comes last), so the secret a key file belongs to is unambiguous, see
// existingKeyFiles.
func getLocalKeyFilename(namespace, name, filename, hashString string) string {
	return strings.Join([]string{hashString, namespace, name, filename}, keyFileSep)
}

// fileExists returns true if the file exists
// errors from Stat are not handled, as this is a optimistic check, if a false
// negative results, it is still fine for our usecase
func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil
}
