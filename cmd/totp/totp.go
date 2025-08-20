package cmd

import (
	"tinyauth/cmd/totp/generate"

	"github.com/spf13/cobra"
)

func TotpCmd() *cobra.Command {
	totpCmd := &cobra.Command{
		Use:   "totp",
		Short: "Totp utilities",
		Long:  `Utilities for creating and verifying totp codes.`,
	}
	totpCmd.AddCommand(generate.GenerateCmd)
	return totpCmd
}
