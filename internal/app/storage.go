package app

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func loadStore() map[string]EncryptedData {
	store := make(map[string]EncryptedData)

	if _, err := os.Stat(storagePath); os.IsNotExist(err) {
		return store
	}

	data, err := os.ReadFile(storagePath)
	if err != nil {
		panic("failed to read store: " + err.Error())
	}

	if err := json.Unmarshal(data, &store); err != nil {
		panic("failed to parse store: " + err.Error())
	}

	return store
}

func saveStore(store map[string]EncryptedData) {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		panic("failed to marshal store: " + err.Error())
	}

	if err := os.MkdirAll(filepath.Dir(storagePath), 0700); err != nil {
		panic("failed to create config directory: " + err.Error())
	}

	if err := os.WriteFile(storagePath, data, 0600); err != nil {
		panic("failed to write store: " + err.Error())
	}
}
