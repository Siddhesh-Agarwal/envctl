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
		createExportCommand(),
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

func createVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the version of envctl",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("envctl version: %s\n", app.Version)
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

func createExportCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "export <key> [filename]",
		Short: "Export a key's value to a .env file",
		Args:  cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			key := args[0]
			filename := ".env"
			if len(args) > 1 {
				filename = args[1]
			}

			password := promptPassword("Enter master password: ")
			value, err := app.RetrieveDecryptedValue(key, password)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}

			//Create .env file if it doesn't exist.  Append if it does.
			file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating/opening .env file: %v\n", err)
				os.Exit(1)
			}
			defer file.Close()

			if _, err := file.WriteString(fmt.Sprintf("%s=\"%s\"\n", key, value)); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing to .env file: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Key '%s' exported to '%s'\n", key, filename)
		},
	}
}

func promptPassword(prompt string) []byte {
	fmt.Print(prompt)
	password, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	return password
}
