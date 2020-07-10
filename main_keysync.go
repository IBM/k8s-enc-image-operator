package main

import (
	"flag"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/lumjjb/k8s-enc-image-operator/keysync"
)

func main() {

	inputFlags := struct {
		kubeconfig string
		interval   string
		dir        string
	}{
		kubeconfig: "",
		interval:   "10s",
		dir:        "/tmp/keys",
	}

	flag.StringVar(&inputFlags.kubeconfig, "kubeconfig", inputFlags.kubeconfig,
		"(optional) kubeconfig file to use, defaults to in-cluster config otherwise")
	flag.StringVar(&inputFlags.interval, "interval", inputFlags.interval,
		"(optional) interval to sync decryption keys")
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

	// TODO: Take in flags from args
	interval := 30 * time.Second
	dir := "/tmp/keys"

	ks := &keysync.KeySyncServer{
		K8sClient:  clientset,
		Interval:   interval,
		KeySyncDir: dir,
	}
	if err := ks.Start(); err != nil {
		logrus.Fatalf("KeySync failure: %v", err)
	}
}
