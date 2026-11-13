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
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	keyprotect "github.com/lumjjb/k8s-enc-image-operator/keyprotect"
	"github.com/lumjjb/k8s-enc-image-operator/keysync"
	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	NamespaceEnv = "POD_NAMESPACE"
)

func main() {
	inputFlags := struct {
		kubeconfig                 string
		interval                   uint
		dir                        string
		keyprotectConfigFile       string
		keyprotectConfigKubeSecret string
		keyFilePermissions         string
		keyFileOwnership           string
	}{
		kubeconfig:                 "",
		interval:                   10,
		dir:                        "/tmp/keys",
		keyprotectConfigFile:       "",
		keyprotectConfigKubeSecret: "",
		keyFilePermissions:         "0600",
		keyFileOwnership:           "",
	}

	flag.StringVar(&inputFlags.kubeconfig, "kubeconfig", inputFlags.kubeconfig,
		"(optional) kubeconfig file to use, defaults to in-cluster config otherwise")
	flag.UintVar(&inputFlags.interval, "interval", inputFlags.interval,
		"(optional) interval to sync decryption keys (in seconds)")
	flag.StringVar(&inputFlags.dir, "dir", inputFlags.dir,
		"(optional) directory to sync keys to")
	flag.StringVar(&inputFlags.keyprotectConfigFile, "keyprotectConfigFile", inputFlags.keyprotectConfigFile,
		"(optional) config file for keyprotect enablement")
	flag.StringVar(&inputFlags.keyprotectConfigKubeSecret, "keyprotectConfigKubeSecret", inputFlags.keyprotectConfigKubeSecret,
		"(optional) kube secret name for config file for keyprotect enablement")
	flag.StringVar(&inputFlags.keyFilePermissions, "keyFilePermissions", inputFlags.keyFilePermissions,
		"(optional) permissions for the created key files (defaults to 0600)")
	flag.StringVar(&inputFlags.keyFileOwnership, "keyFileOwnership", inputFlags.keyFileOwnership,
		"(optional) ownership for the created key files (in UID:GID format; if not provided key files will be created with UID:GID of the process)")
	flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", inputFlags.kubeconfig)
	if err != nil {
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	keyFilePermissions, err := parseKeyFilePermissions(inputFlags.keyFilePermissions)
	if err != nil {
		panic(err)
	}

	keyFileOwnerUID, keyFileOwnerGID, err := parseKeyFileOwnership(inputFlags.keyFileOwnership)
	if err != nil {
		panic(err)
	}

	interval, err := parseInterval(inputFlags.interval)
	if err != nil {
		panic(err)
	}

	namespace := os.Getenv(NamespaceEnv)

	ksc := keysync.KeySyncServerConfig{
		K8sClient:          clientset,
		Interval:           interval,
		KeySyncDir:         inputFlags.dir,
		Namespace:          namespace,
		KeyFilePermissions: keyFilePermissions,
		KeyFileOwnerUID:    keyFileOwnerUID,
		KeyFileOwnerGID:    keyFileOwnerGID,
	}
	ks := keysync.NewKeySyncServer(ksc)

	if inputFlags.keyprotectConfigFile != "" {
		kpskh, err := keyprotect.GetSecKeyHandlerFromConfigFile(inputFlags.keyprotectConfigFile)
		if err != nil {
			panic(err)
		}
		ks.AddSecretKeyHandler("kp-key", kpskh)
	} else if inputFlags.keyprotectConfigKubeSecret != "" {
		go keyprotectConfigKubeSecretThread(clientset, namespace, inputFlags.keyprotectConfigKubeSecret, ks.AddSecretKeyHandler, interval)
		/*
			secClient := clientset.CoreV1().Secrets(namespace)
			s, err := secClient.Get(inputFlags.keyprotectConfigKubeSecret, metav1.GetOptions{})
			if err != nil {
				panic(err)
			}
			if s.Data != nil {
				d := s.Data["config.json"]
				if len(d) > 0 {
					kpskh, err := keyprotect.GetSecKeyHandlerFromConfig(d)
					if err != nil {
						panic(err)
					}
					ks.AddSecretKeyHandler("kp-key", kpskh)
				}
			}
		*/
	}

	slog.Info("Starting KeySync server",
		"syncDir", ksc.KeySyncDir,
		"interval", ksc.Interval,
		"namespace", ksc.Namespace)

	slog.Info("Private key files will be persisted with permissions",
		"permissions", ksc.KeyFilePermissions)

	if ksc.KeyFileOwnerUID != nil && ksc.KeyFileOwnerGID != nil {
		slog.Info("Private key files will be persisted with ownership (this might not work unless running as root or having CAP_CHOWN)",
			"uid", *ksc.KeyFileOwnerUID,
			"gid", *ksc.KeyFileOwnerGID)
	}

	if err := ks.Start(); err != nil {
		slog.Error("KeySync failure", "error", err)
		os.Exit(1)
	}
}

// parseKeyFilePermissions parses an octal permission string such as "0600".
func parseKeyFilePermissions(s string) (os.FileMode, error) {
	perm, err := strconv.ParseUint(s, 8, 32)
	if err != nil || perm > 0777 {
		return 0, fmt.Errorf("invalid permissions specified: %q", s)
	}
	return os.FileMode(perm), nil
}

// parseKeyFileOwnership parses an ownership string in UID:GID format. An empty
// string means the ownership is not changed and returns nil for both.
func parseKeyFileOwnership(s string) (*int, *int, error) {
	if s == "" {
		return nil, nil, nil
	}
	uidStr, gidStr, ok := strings.Cut(s, ":")
	if !ok {
		return nil, nil, fmt.Errorf("invalid ownership specified: %q", s)
	}
	uid, uidErr := strconv.Atoi(uidStr)
	gid, gidErr := strconv.Atoi(gidStr)
	if uidErr != nil || gidErr != nil || uid < 0 || gid < 0 || uid > int(math.MaxUint32) || gid > int(math.MaxUint32) {
		return nil, nil, fmt.Errorf("invalid ownership specified: %q", s)
	}
	return &uid, &gid, nil
}

// parseInterval converts the interval in seconds to a duration.
func parseInterval(seconds uint) (time.Duration, error) {
	if uint64(seconds) > uint64(math.MaxInt64/time.Second) {
		return 0, fmt.Errorf("interval %d s is too large", seconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

// keyprotectConfigKubeSecretThread is a helper function that tries to retrieve the kube secret containing the
// keyprotect config and add the handler to the key sync server. Meant to run as a thread.
func keyprotectConfigKubeSecretThread(clientset kubernetes.Interface, namespace string, secretName string, addHandler addSecretKeyHandlerFunc, interval time.Duration) {
	oldData := ""
	for {
		oldData = syncKeyprotectConfig(clientset, namespace, secretName, addHandler, oldData)
		<-time.After(interval)
	}
}

// addSecretKeyHandlerFunc registers a secret key handler, i.e.
// (*keysync.KeySyncServer).AddSecretKeyHandler.
type addSecretKeyHandlerFunc func(secretType string, skh sechandlers.SecretKeyHandler)

// syncKeyprotectConfig reads the keyprotect config from the kube secret and,
// if it changed since oldData, registers a keyprotect handler for it. It
// returns the config data to compare against on the next call.
func syncKeyprotectConfig(clientset kubernetes.Interface, namespace string, secretName string, addHandler addSecretKeyHandlerFunc, oldData string) string {
	secClient := clientset.CoreV1().Secrets(namespace)
	s, err := secClient.Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return oldData
	}

	d := s.Data["config.json"]
	if len(d) == 0 || string(d) == oldData {
		return oldData
	}

	slog.Info("New keyprotect config detected in secrets, configuring...")
	kpskh, err := keyprotect.GetSecKeyHandlerFromConfig(d)
	if err != nil {
		slog.Error("Unable to parse keyprotect config", "error", err)
		// Remember the invalid config so it is not re-parsed on every
		// interval; a changed config is picked up again.
		return string(d)
	}
	addHandler("kp-key", kpskh)
	return string(d)
}
