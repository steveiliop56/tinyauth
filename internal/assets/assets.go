package assets

import (
	"embed"
)

//go:embed dist
var Assets embed.FS

//go:embed VERSION
var Version string