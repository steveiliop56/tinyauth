package cmd

import (
	"fmt"
	"tinyauth/internal/config"

	"github.com/spf13/cobra"
)

type versionCmd struct {
	root *cobra.Command
	cmd  *cobra.Command
}

func newVersionCmd(root *cobra.Command) *versionCmd {
	return &versionCmd{
		root: root,
	}
}

func (c *versionCmd) Register() {
	c.cmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of Tinyauth",
		Long:  `All software has versions. This is Tinyauth's.`,
		Run:   c.run,
	}

	if c.root != nil {
		c.root.AddCommand(c.cmd)
	}
}

func (c *versionCmd) GetCmd() *cobra.Command {
	return c.cmd
}

func (c *versionCmd) run(cmd *cobra.Command, args []string) {
	fmt.Printf("Version: %s\n", config.Version)
	fmt.Printf("Commit Hash: %s\n", config.CommitHash)
	fmt.Printf("Build Timestamp: %s\n", config.BuildTimestamp)
}
