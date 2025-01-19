package cmd

import (
	"os"
	"tinyauth/internal/api"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tinyauth",
	Short: "A dead simple login page for your apps.",
	Long: `Tinyauth is an extremely simple traefik forward-auth login screen that makes securing your apps easy.`,
	Run: func(cmd *cobra.Command, args []string) {
		api.Run()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
