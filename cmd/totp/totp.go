package cmd

import (
	"tinyauth/cmd/totp/generate"

	"github.com/spf13/cobra"
)

func TotpCmd() *cobra.Command {
	// Create the totp command
	totpCmd := &cobra.Command{
		Use:   "totp",
		Short: "Totp utilities",
		Long:  `Utilities for creating and verifying totp codes.`,
	}

	// Add the generate command
	totpCmd.AddCommand(generate.GenerateCmd)

	// Return the totp command
	return totpCmd
}
