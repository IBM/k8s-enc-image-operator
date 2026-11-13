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
	"time"

	keyprotect "github.com/lumjjb/k8s-enc-image-operator/keyprotect"
	"github.com/lumjjb/k8s-enc-image-operator/keysync"
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

	var keyFilePermissions uint32
	n, err := fmt.Sscanf(inputFlags.keyFilePermissions, "%o", &keyFilePermissions)
	if err != nil || n != 1 {
		panic("invalid permissions specified")
	}

	var keyFileOwnerUID, keyFileOwnerGID *int
	if inputFlags.keyFileOwnership != "" {
		keyFileOwnerUID, keyFileOwnerGID = new(int), new(int)
		n, err = fmt.Sscanf(inputFlags.keyFileOwnership, "%d:%d", keyFileOwnerUID, keyFileOwnerGID)
		if err != nil || n != 2 || *keyFileOwnerUID < 0 || *keyFileOwnerGID < 0 {
			panic("invalid ownership specified")
		}
	}

	namespace := os.Getenv(NamespaceEnv)
	if inputFlags.interval > math.MaxInt64 {
		panic("input interval caused conversion overflow")
	}
	interval := time.Duration(inputFlags.interval) * time.Second

	ksc := keysync.KeySyncServerConfig{
		K8sClient:          clientset,
		Interval:           interval,
		KeySyncDir:         inputFlags.dir,
		Namespace:          namespace,
		KeyFilePermissions: os.FileMode(keyFilePermissions),
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
		go keyprotectConfigKubeSecretThread(clientset, namespace, inputFlags.keyprotectConfigKubeSecret, ks, interval)
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

// keyprotectConfigKubeSecretThread is a helper function that tries to retrieve the kube secret containing the
// keyprotect config and add the handler to the key sync server. Meant to run as a thread.
func keyprotectConfigKubeSecretThread(clientset kubernetes.Interface, namespace string, secretName string, ks *keysync.KeySyncServer, interval time.Duration) {
	first := true
	oldData := ""
	for {
		if !first {
			<-time.After(interval)
		} else {
			first = false
		}

		secClient := clientset.CoreV1().Secrets(namespace)
		s, err := secClient.Get(context.Background(), secretName, metav1.GetOptions{})
		if err != nil {
			continue
		}

		if s.Data != nil {
			d := s.Data["config.json"]
			if len(d) > 0 {
				if string(d) == oldData {
					continue
				}
				oldData = string(d)

				slog.Info("New keyprotect config detected in secrets, configuring...")
				kpskh, err := keyprotect.GetSecKeyHandlerFromConfig(d)
				if err != nil {
					slog.Error("Unable to parse keyprotect config", "error", err)
					continue
				}
				ks.AddSecretKeyHandler("kp-key", kpskh)
			}
		}
	}
}
