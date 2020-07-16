package keysync

import (
	"time"
    "fmt"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

    // Namespace specifies the namespace where key secrets are stored
    Namespace string
}


// Start begins running the KeySyncServer according to the parameters
// specified
func (ks *KeySyncServer) Start() error {
    secClient := ks.K8sClient.CoreV1().Secrets(ks.Namespace)

	for {
		select {
		case <-time.After(ks.Interval):
            secList , err := secClient.List(metav1.ListOptions{})
            if err != nil {
                logrus.Errorf("Error listing secrets: %v", err)
                continue
            }
            fmt.Println(secList)
		}
	}
	return nil
}
