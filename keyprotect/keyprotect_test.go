// Copyright 2020, 2026 k8s-enc-image-operator authors.
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

package keyprotect

import (
	"os"
	"path/filepath"
	"testing"
)

const validConfig = `{
	"keyprotect-url": "https://us-south.kms.cloud.ibm.com",
	"instance-id": "a3c5e3g5-9ef7-4838-a285-398efb23e6f3",
	"apikey": "apikey"
}`

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGetSecKeyHandlerFromConfig(t *testing.T) {
	skh, err := GetSecKeyHandlerFromConfig([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if skh == nil {
		t.Fatal("expected a handler")
	}
}

func TestGetSecKeyHandlerFromConfigErrors(t *testing.T) {
	for name, config := range map[string]string{
		"empty":           "",
		"invalid json":    "{not json",
		"wrong type":      `{"apikey": 1}`,
		"missing apikey":  `{"keyprotect-url": "https://us-south.kms.cloud.ibm.com", "instance-id": "id"}`,
		"invalid url":     `{"keyprotect-url": "{https://us-south.kms.cloud.ibm.com}", "instance-id": "id", "apikey": "apikey"}`,
		"invalid api key": `{"keyprotect-url": "https://us-south.kms.cloud.ibm.com", "instance-id": "id", "apikey": "\"apikey\""}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := GetSecKeyHandlerFromConfig([]byte(config)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestGetSecKeyHandlerFromConfigFile(t *testing.T) {
	skh, err := GetSecKeyHandlerFromConfigFile(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if skh == nil {
		t.Fatal("expected a handler")
	}
}

func TestGetSecKeyHandlerFromConfigFileErrors(t *testing.T) {
	if _, err := GetSecKeyHandlerFromConfigFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	if _, err := GetSecKeyHandlerFromConfigFile(writeConfig(t, "{not json")); err == nil {
		t.Fatal("expected an error for an invalid config file")
	}
}
