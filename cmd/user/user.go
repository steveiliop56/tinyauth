package cmd

import (
	"tinyauth/cmd/user/create"
	"tinyauth/cmd/user/verify"

	"github.com/spf13/cobra"
)

func UserCmd() *cobra.Command {
	userCmd := &cobra.Command{
		Use:  "user",
		Short: "User utilities",
		Long: `Utilities for creating and verifying tinyauth compatible users.`,
	}
	userCmd.AddCommand(create.CreateCmd)
	userCmd.AddCommand(verify.VerifyCmd)
	return userCmd
}	