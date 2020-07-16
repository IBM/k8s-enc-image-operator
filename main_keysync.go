package main

import (
	"flag"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/lumjjb/k8s-enc-image-operator/keysync"
)

const (
	NamespaceEnv = "POD_NAMESPACE"
)

func main() {
	inputFlags := struct {
		kubeconfig string
		interval   uint
		dir        string
	}{
		kubeconfig: "",
		interval:   10,
		dir:        "/tmp/keys",
	}

	flag.StringVar(&inputFlags.kubeconfig, "kubeconfig", inputFlags.kubeconfig,
		"(optional) kubeconfig file to use, defaults to in-cluster config otherwise")
	flag.UintVar(&inputFlags.interval, "interval", inputFlags.interval,
		"(optional) interval to sync decryption keys (in seconds)")
	flag.StringVar(&inputFlags.dir, "dir", inputFlags.dir,
		"(optional) directory to sync keys to")
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

	ks := &keysync.KeySyncServer{
		K8sClient:  clientset,
		Interval:   time.Duration(inputFlags.interval) * time.Second,
		KeySyncDir: inputFlags.dir,
		Namespace:  namespace,
	}

	logrus.Printf("Starting KeySync server with sync-dir %v, interval %v s, namespace %v",
		ks.KeySyncDir,
		ks.Interval/time.Second,
		ks.Namespace)

	if err := ks.Start(); err != nil {
		logrus.Fatalf("KeySync failure: %v", err)
	}
}
