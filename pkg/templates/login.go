package templates

import (
	_ "embed"
)

//go:embed login.html
var LoginTemplate string

//go:embed error.html
var ErrorTemplate string
