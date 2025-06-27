package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

// Secret represents an environment secret
type Secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Store represents the encrypted storage for secrets
type Store struct {
	Salt       string   `json:"salt"`
	Nonce      string   `json:"nonce"`
	Ciphertext string   `json:"ciphertext"`
	Keys       []string `json:"keys"`
}

const (
	// Number of PBKDF2 iterations
	iterations = 10000
	// AES-256
	keySize = 32
)

// Global variables
var (
	storePath string
	secrets   map[string]string
)

func init() {
	// Determine the user's home directory for storing the secrets file
	usr, err := user.Current()
	if err != nil {
		fmt.Println("Error getting user home directory:", err)
		os.Exit(1)
	}

	// Set the default store path in the user's home directory
	storePath = filepath.Join(usr.HomeDir, ".envctl.json")

	// Initialize the secrets map
	secrets = make(map[string]string)
}

// generateRandomBytes generates random bytes of the specified length
func generateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// deriveKey derives an encryption key from a password using PBKDF2
func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
}

// encrypt encrypts data using AES-GCM
func encrypt(data []byte, password string) ([]byte, []byte, []byte, error) {
	// Generate salt for key derivation
	salt, err := generateRandomBytes(16)
	if err != nil {
		return nil, nil, nil, err
	}

	// Derive key from password and salt
	key := deriveKey(password, salt)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate nonce
	nonce, err := generateRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, nil, err
	}

	// Encrypt data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	return ciphertext, salt, nonce, nil
}

// decrypt decrypts data using AES-GCM
func decrypt(ciphertext, salt, nonce []byte, password string) ([]byte, error) {
	// Derive key from password and salt
	key := deriveKey(password, salt)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// promptPassword prompts the user to enter a password without echoing it
func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// promptConfirmPassword prompts for password and confirms it
func promptConfirmPassword() (string, error) {
	password, err := promptPassword("Enter master password: ")
	if err != nil {
		return "", err
	}

	confirm, err := promptPassword("Confirm master password: ")
	if err != nil {
		return "", err
	}

	if password != confirm {
		return "", errors.New("passwords do not match")
	}

	return password, nil
}

// storeExists checks if the store file exists
func storeExists() bool {
	_, err := os.Stat(storePath)
	return !os.IsNotExist(err)
}

// saveStore saves the secrets to the store file
func saveStore(password string) error {
	// Convert secrets map to JSON
	secretsData, err := json.Marshal(secrets)
	if err != nil {
		return err
	}

	// Encrypt secrets
	ciphertext, salt, nonce, err := encrypt(secretsData, password)
	if err != nil {
		return err
	}

	// Create store
	store := Store{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Keys:       make([]string, 0, len(secrets)),
	}

	// Add keys to store for listing
	for k := range secrets {
		store.Keys = append(store.Keys, k)
	}

	// Convert store to JSON
	storeData, err := json.Marshal(store)
	if err != nil {
		return err
	}

	// Write store to file
	return os.WriteFile(storePath, storeData, 0600)
}

// loadStore loads the secrets from the store file
func loadStore(password string) error {
	// Read store from file
	storeData, err := os.ReadFile(storePath)
	if err != nil {
		return err
	}

	// Parse store
	var store Store
	if err := json.Unmarshal(storeData, &store); err != nil {
		return err
	}

	// Decode salt, nonce, and ciphertext
	salt, err := base64.StdEncoding.DecodeString(store.Salt)
	if err != nil {
		return err
	}

	nonce, err := base64.StdEncoding.DecodeString(store.Nonce)
	if err != nil {
		return err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(store.Ciphertext)
	if err != nil {
		return err
	}

	// Decrypt secrets
	secretsData, err := decrypt(ciphertext, salt, nonce, password)
	if err != nil {
		return errors.New("invalid password or corrupted data")
	}

	// Parse secrets
	return json.Unmarshal(secretsData, &secrets)
}

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "envctl",
	Short: "A tool for managing environment secrets",
	Long:  `envctl is a CLI tool for securely storing and managing environment secrets.`,
}

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the secrets store",
	Long:  `Initialize the secrets store with a master password.`,
	Run: func(cmd *cobra.Command, args []string) {
		if storeExists() {
			fmt.Println("Store already exists. Use other commands to manage secrets.")
			return
		}

		password, err := promptConfirmPassword()
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if err := saveStore(password); err != nil {
			fmt.Println("Error initializing store:", err)
			return
		}

		fmt.Println("Store initialized successfully.")
	},
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all secret keys",
	Long:    `List all the keys of the stored secrets.`,
	Aliases: []string{"ls"},
	Run: func(cmd *cobra.Command, args []string) {
		if !storeExists() {
			fmt.Println("Store does not exist. Run 'envctl init' first.")
			return
		}

		password, err := promptPassword("Enter master password: ")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if err := loadStore(password); err != nil {
			fmt.Println("Error loading store:", err)
			return
		}

		if len(secrets) == 0 {
			fmt.Println("No secrets found.")
			return
		}

		fmt.Println("Available secrets:")
		for k := range secrets {
			fmt.Println("-", k)
		}
	},
}

// setCmd represents the set command
var setCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a secret",
	Long:  `Set a secret key-value pair.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !storeExists() {
			fmt.Println("Store does not exist. Run 'envctl init' first.")
			return
		}

		key := args[0]
		value, err := promptPassword("Enter secret value: ")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		password, err := promptPassword("Enter master password: ")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if err := loadStore(password); err != nil {
			fmt.Println("Error loading store:", err)
			return
		}

		// Set the secret
		secrets[key] = value

		if err := saveStore(password); err != nil {
			fmt.Println("Error saving store:", err)
			return
		}

		fmt.Printf("Secret '%s' set successfully.\n", key)
	},
}

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Get a secret",
	Long:  `Get the value of a secret by its key.`,
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !storeExists() {
			fmt.Println("Store does not exist. Run 'envctl init' first.")
			return
		}

		key := args[0]

		password, err := promptPassword("Enter master password: ")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if err := loadStore(password); err != nil {
			fmt.Println("Error loading store:", err)
			return
		}

		value, exists := secrets[key]
		if !exists {
			fmt.Printf("Secret '%s' not found.\n", key)
			return
		}

		fmt.Println(value)
	},
}

// removeCmd represents the remove command
var removeCmd = &cobra.Command{
	Use:     "remove [key]",
	Short:   "Remove a secret",
	Long:    `Remove a secret by its key.`,
	Aliases: []string{"rm"},
	Args:    cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !storeExists() {
			fmt.Println("Store does not exist. Run 'envctl init' first.")
			return
		}

		key := args[0]

		password, err := promptPassword("Enter master password: ")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if err := loadStore(password); err != nil {
			fmt.Println("Error loading store:", err)
			return
		}

		if _, exists := secrets[key]; !exists {
			fmt.Printf("Secret '%s' not found.\n", key)
			return
		}

		delete(secrets, key)

		if err := saveStore(password); err != nil {
			fmt.Println("Error saving store:", err)
			return
		}

		fmt.Printf("Secret '%s' removed successfully.\n", key)
	},
}

var exportCmd = &cobra.Command{
	Use:   "export [key]",
	Short: "Export a secret to a .env file",
	Long:  "Export a secret to a .env file in the current directory. If no .env file exists, it will be created.",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !storeExists() {
			fmt.Println("Store does not exist. Run 'envctl init' first.")
			return
		}
		password, err := promptPassword("Enter master password: ")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if err := loadStore(password); err != nil {
			fmt.Println("Error loading store:", err)
			return
		}

		for _, key := range args {
			value, exists := secrets[key]
			if !exists {
				fmt.Printf("Secret '%s' not found.\n", key)
				continue
			}

			filename := fmt.Sprintf("%s.env", key)
			file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				fmt.Printf("Error opening file '%s': %v\n", filename, err)
				continue
			}
			defer file.Close()

			_, err = file.WriteString(fmt.Sprintf("%s=%s\n", key, value))
			if err != nil {
				fmt.Printf("Error writing to file '%s': %v\n", filename, err)
				continue
			}

			fmt.Printf("Secret '%s' exported to '%s'.\n", key, filename)
		}
		fmt.Println("Export completed.")
	},
}

func main() {
	// Add commands to root command
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(removeCmd)
	rootCmd.AddCommand(exportCmd)

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
