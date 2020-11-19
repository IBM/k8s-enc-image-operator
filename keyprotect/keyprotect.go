package keyprotect

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	kpsh "github.com/lumjjb/k8s-enc-image-operator/keyprotect/sechandler"
	sechandlers "github.com/lumjjb/k8s-enc-image-operator/keysync/sechandlers"
)

// keyprotectConfig example, is a json in the following format
// {
//     "keyprotect-url": "https://us-south.kms.cloud.ibm.com",
//     "instance-id": "a3c5e3g5-9ef7-4838-a285-398efb23e6f3",
//     "apikey": "ZWh0YWVyZwbvHwo-345mfwSOST6wtdMFqeLcdE4Tsxbz",
// }
type keyprotectConfig struct {
	KeyprotectUrl string `json:"keyprotect-url"`
	InstanceId    string `json:"instance-id"`
	Apikey        string `json:"apikey"`
}

// GetSecKeyHandlerFromConfig returns a secrethandler for key protect given a configuration
// file for key protect
func GetSecKeyHandlerFromConfig(kpconfigPath string) (sechandlers.SecretKeyHandler, error) {
	data, err := ioutil.ReadFile(filepath.Clean(kpconfigPath))
	if err != nil {
		return nil, err
	}

	var kpc keyprotectConfig
	err = json.Unmarshal(data, &kpc)
	if err != nil {
		return nil, err
	}

	secHandler, err := kpsh.NewKeyprotectSecretKeyHandler(kpc.KeyprotectUrl,
		kpc.InstanceId,
		kpc.Apikey)
	if err != nil {
		return nil, err
	}

	return secHandler, nil
}
