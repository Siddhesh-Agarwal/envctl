package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Siddhesh-Agarwal/envctl/internal/app"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "envctl",
		Short: "Secure environment variable manager",
	}

	rootCmd.AddCommand(
		createSetCommand(),
		createGetCommand(),
		createListCommand(),
		createDeleteCommand(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func createSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Store an encrypted key-value pair",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			key, value := args[0], args[1]
			password := promptPassword("Enter encryption password: ")
			app.StoreEncryptedValue(key, value, password)
			fmt.Println("Key stored successfully")
		},
	}
}

func createGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Retrieve a decrypted value",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]
			password := promptPassword("Enter master password: ")
			value, err := app.RetrieveDecryptedValue(key, password)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(value)
		},
	}
}

func createListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all stored keys",
		Run: func(cmd *cobra.Command, args []string) {
			keys := app.ListStoredKeys()
			if len(keys) == 0 {
				fmt.Println("No keys stored")
				return
			}
			sort.Strings(keys) // sort the keys
			for _, key := range keys {
				fmt.Println(key)
			}
		},
	}
}

func createDeleteCommand() *cobra.Command {
	deleteCmd := &cobra.Command{
		Use:   "delete <key>",
		Short: "Delete a stored key",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]
			force, err := cmd.Flags().GetBool("yes")
			if err != nil {
				fmt.Println(err)
				return
			}
			if !force {
				fmt.Printf("Are you sure you want to delete key '%s'? (y/N) ", key)
				var response string
				fmt.Scanf("%s\n", &response)
				if strings.ToLower(response) != "y" {
					fmt.Println("Deletion cancelled")
					return
				}
			}
			app.DeleteKey(key)
			fmt.Println("Key deleted successfully")
		},
	}
	deleteCmd.Flags().BoolP("yes", "y", false, "force deletion without confirmation")
	return deleteCmd
}

func promptPassword(prompt string) []byte {
	fmt.Print(prompt)
	password, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return password
}
