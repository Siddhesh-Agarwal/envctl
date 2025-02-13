package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	iterations = 600_000
	keyLength  = 32
	saltSize   = 16
)

type EncryptedData struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

var storagePath = getStoragePath()

func getStoragePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".envctl", "secure_store.json")
}

func StoreEncryptedValue(key, value string, password []byte) {
	store := loadStore()
	defer clearSensitiveData(password)

	salt := generateSalt()
	encryptionKey := deriveKey(password, salt)
	nonce, ciphertext := encryptData([]byte(value), encryptionKey)

	store[key] = EncryptedData{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	saveStore(store)
}

func RetrieveDecryptedValue(key string, password []byte) (string, error) {
	store := loadStore()
	defer clearSensitiveData(password)

	data, exists := store[key]
	if !exists {
		return "", fmt.Errorf("key '%s' not found", key)
	}

	encryptionKey := deriveKey(password, data.Salt)
	plaintext, err := decryptData(data, encryptionKey)
	if err != nil {
		return "", errors.New("decryption failed: invalid password or corrupted data")
	}

	return string(plaintext), nil
}

func ListStoredKeys() []string {
	store := loadStore()
	keys := make([]string, 0, len(store))
	for k := range store {
		keys = append(keys, k)
	}
	return keys
}

func DeleteKey(key string) {
	store := loadStore()
	delete(store, key)
	saveStore(store)
}
