package sechandlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	kp "github.com/IBM/keyprotect-go-client"
	"github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
	"github.com/pkg/errors"
)

type keyprotectSecretKeyHandler struct {
	kpClient *kp.Client
}

// keyprotectWrappedKey encapsulates the struct of the wrapped key as returned
// by keyprotect. The example key looks like:
// {
//     "ciphertext": "eyJjBoZXJ.........0Z1YmYwIn0=",
//     "keyVersion": {
//         "id": "27b941a0-ab34-4b92-960d-30fa80f15bf0"
//     }
// }
type keyprotectWrappedKey struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion struct {
		Id string `json:"id"`
	} `json:"keyVersion"`
}

// handleSecret unwraps the keys by calling the key protect unwrap service
func (skh *keyprotectSecretKeyHandler) handleSecret(data map[string][]byte) (map[string][]byte, error) {
	var err error
	retdata := map[string][]byte{}

	for filename, kpjson := range data {
		var wk keyprotectWrappedKey
		err = json.Unmarshal(kpjson, &wk)
		if err != nil {
			return nil, err
		}

		// Check for parsed fields
		if len(wk.KeyVersion.Id) == 0 {
			return nil, errors.New("KeyVersion.Id field is empty")
		}
		if len(wk.Ciphertext) == 0 {
			return nil, errors.New("Ciphertext field is empty")
		}

		b64content, err := skh.kpClient.Unwrap(context.TODO(), wk.KeyVersion.Id, []byte(wk.Ciphertext), nil)
		if err != nil {
			return nil, err
		}

		var content []byte
		content, err = base64.StdEncoding.DecodeString(string(b64content))
		if err != nil {
			return nil, err
		}

		retdata[filename] = content
	}
	return retdata, nil
}

// NewKeyprotectSecretKeyHandler returns a secret handler for keyprotect given the keyprotect configuration
func NewKeyprotectSecretKeyHandler(kpUrl, instanceid, apikey string) (sechandlers.SecretKeyHandler, error) {
	cc := kp.ClientConfig{
		BaseURL:    kpUrl,
		APIKey:     apikey,
		InstanceID: instanceid,
	}

	kpClient, err := kp.New(cc, kp.DefaultTransport())
	if err != nil {
		return nil, err
	}

	kpskh := keyprotectSecretKeyHandler{
		kpClient: kpClient,
	}

	return func(data map[string][]byte) (map[string][]byte, error) {
		return kpskh.handleSecret(data)
	}, nil
}
