package cmd

import (
	"fmt"
	"tinyauth/internal/constants"

	"github.com/spf13/cobra"
)

// Create the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of Tinyauth",
	Long:  `All software has versions. This is Tinyauth's`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Version: %s\n", constants.Version)
		fmt.Printf("Commit Hash: %s\n", constants.CommitHash)
		fmt.Printf("Build Timestamp: %s\n", constants.BuildTimestamp)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
