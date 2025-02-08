package assets

import (
	"embed"
)

// UI assets
//
//go:embed dist
var Assets embed.FS

// Version file
//
//go:embed version
var Version string
