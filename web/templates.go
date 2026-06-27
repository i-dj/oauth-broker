package web

import "embed"

// Templates contains HTML templates used by the broker web pages.
//
//go:embed templates/*.html
var Templates embed.FS
