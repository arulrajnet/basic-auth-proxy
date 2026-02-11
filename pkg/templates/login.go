// Package templates contains HTML templates for the login page.
package templates

import (
	_ "embed"
)

// LoginTemplate is the HTML template for the login page.
//
//go:embed login.html
var LoginTemplate string

// ErrorTemplate is the HTML template for the error page.
//
//go:embed error.html
var ErrorTemplate string
