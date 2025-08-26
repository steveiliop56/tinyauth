package assets

import (
	"embed"
)

// Frontend assets
//
//go:embed dist
var FrontendAssets embed.FS
