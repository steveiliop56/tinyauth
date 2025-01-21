package cmd

import (
	"tinyauth/cmd/user/subcommands"

	"github.com/spf13/cobra"
)

func UserCmd() *cobra.Command {
	userCmd := &cobra.Command{
		Use:  "user",
		Short: "User utilities",
		Long: `Utilities for creating and verifying tinyauth compatible users.`,
	}
	userCmd.AddCommand(subcommands.CreateCmd)
	return userCmd
}	