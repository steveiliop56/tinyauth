package cmd

import (
	"fmt"
	"tinyauth/internal/config"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Tinyauth",
	Long:  `All software has versions. This is Tinyauth's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s\n", config.Version)
		fmt.Printf("Commit Hash: %s\n", config.CommitHash)
		fmt.Printf("Build Timestamp: %s\n", config.BuildTimestamp)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
