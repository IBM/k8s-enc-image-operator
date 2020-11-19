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
		kubeconfig       string
		interval         uint
		dir              string
		keyprotectConfig string
	}{
		kubeconfig:       "",
		interval:         10,
		dir:              "/tmp/keys",
		keyprotectConfig: "",
	}

	flag.StringVar(&inputFlags.kubeconfig, "kubeconfig", inputFlags.kubeconfig,
		"(optional) kubeconfig file to use, defaults to in-cluster config otherwise")
	flag.UintVar(&inputFlags.interval, "interval", inputFlags.interval,
		"(optional) interval to sync decryption keys (in seconds)")
	flag.StringVar(&inputFlags.dir, "dir", inputFlags.dir,
		"(optional) directory to sync keys to")
	flag.StringVar(&inputFlags.keyprotectConfig, "keyprotectConfig", inputFlags.keyprotectConfig,
		"(optional) config file for keyprotect enablement")

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
		if err != nil {
			panic(err)
		}
		skh["kp-key"] = kpskh
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
