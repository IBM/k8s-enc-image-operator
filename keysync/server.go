package keysync

import (
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

type KeySyncServer struct {
	// clientset
	K8sClient *kubernetes.Clientset

	// query interval
	Interval time.Duration

	// sync directory location
	KeySyncDir string
}

func (ks *KeySyncServer) Start() error {
	for {
		select {
		case <-time.After(ks.Interval):
			logrus.Printf("hello")
		}
	}
	return nil
}
