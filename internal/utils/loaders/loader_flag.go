package loaders

import (
	"fmt"

	"github.com/tinyauthapp/paerser/cli"
	"github.com/tinyauthapp/paerser/flag"
)

type FlagLoader struct{}

func (*FlagLoader) Load(args []string, cmd *cli.Command) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}

	if err := flag.Decode(args, cmd.Configuration); err != nil {
		return false, fmt.Errorf("failed to decode configuration from flags: %w", err)
	}

	return true, nil
}
