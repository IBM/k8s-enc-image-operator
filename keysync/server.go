package keysync

import (
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

// KeySyncServer contains the parameters required for operation of the
// key sync server
type KeySyncServer struct {
	// K8sClient is the k8s clientset to interface with the kubernetes
    // cluster
	K8sClient *kubernetes.Clientset

	// Interval is the query interval in which to sync the decryption keys
	Interval time.Duration

	// KeySyncDir specifies the directory where keys are synced to
	KeySyncDir string
}


// Start begins running the KeySyncServer according to the parameters
// specified
func (ks *KeySyncServer) Start() error {
	for {
		select {
		case <-time.After(ks.Interval):
			logrus.Printf("hello")
		}
	}
	return nil
}
