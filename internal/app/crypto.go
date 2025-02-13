package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func generateSalt() []byte {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		panic("failed to generate salt: " + err.Error())
	}
	return salt
}

func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLength, sha256.New)
}

func encryptData(plaintext, key []byte) ([]byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("failed to create cipher: " + err.Error())
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic("failed to create GCM: " + err.Error())
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic("failed to generate nonce: " + err.Error())
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext
}

func decryptData(data EncryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, data.Nonce, data.Ciphertext, nil)
}

func clearSensitiveData(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
