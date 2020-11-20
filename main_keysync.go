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
	"flag"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	keyprotect "github.com/lumjjb/k8s-enc-image-operator/keyprotect"
	"github.com/lumjjb/k8s-enc-image-operator/keysync"
	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
)

const (
	NamespaceEnv = "POD_NAMESPACE"
)

func main() {
	inputFlags := struct {
		kubeconfig               string
		interval                 uint
		dir                      string
		keyprotectConfig         string
		keyprotectConfigOptional bool
	}{
		kubeconfig:               "",
		interval:                 10,
		dir:                      "/tmp/keys",
		keyprotectConfig:         "",
		keyprotectConfigOptional: false,
	}

	flag.StringVar(&inputFlags.kubeconfig, "kubeconfig", inputFlags.kubeconfig,
		"(optional) kubeconfig file to use, defaults to in-cluster config otherwise")
	flag.UintVar(&inputFlags.interval, "interval", inputFlags.interval,
		"(optional) interval to sync decryption keys (in seconds)")
	flag.StringVar(&inputFlags.dir, "dir", inputFlags.dir,
		"(optional) directory to sync keys to")
	flag.StringVar(&inputFlags.keyprotectConfig, "keyprotectConfig", inputFlags.keyprotectConfig,
		"(optional) config file for keyprotect enablement")
	flag.BoolVar(&inputFlags.keyprotectConfigOptional, "keyprotectConfigOptional", inputFlags.keyprotectConfigOptional,
		"(optional) skip enablement of keyprotect if config file doesn't exist")
	flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", inputFlags.kubeconfig)
	if err != nil {
		panic(err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	namespace := os.Getenv(NamespaceEnv)

	skh := map[string]sechandlers.SecretKeyHandler{}

	if inputFlags.keyprotectConfig != "" {
		kpskh, err := keyprotect.GetSecKeyHandlerFromConfig(inputFlags.keyprotectConfig)
		if err == nil {
			skh["kp-key"] = kpskh
		} else if inputFlags.keyprotectConfigOptional {
			logrus.Printf("Unable to load keyprotect config: %v", err)
		} else {
			panic(err)
		}
	}

	ks := &keysync.KeySyncServer{
		K8sClient:          clientset,
		Interval:           time.Duration(inputFlags.interval) * time.Second,
		KeySyncDir:         inputFlags.dir,
		Namespace:          namespace,
		SpecialKeyHandlers: skh,
	}

	logrus.Printf("Starting KeySync server with sync-dir %v, interval %v s, namespace %v, specialHandlers: %+v",
		ks.KeySyncDir,
		ks.Interval/time.Second,
		ks.Namespace,
		ks.SpecialKeyHandlers)

	if err := ks.Start(); err != nil {
		logrus.Fatalf("KeySync failure: %v", err)
	}
}
