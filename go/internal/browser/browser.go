// Package browser opens a file in the user's default web browser.
package browser

import "os/exec"

// Open launches the given file:// or http(s):// URI in the default browser.
// Returns false if no suitable opener command could be run.
func Open(uri string) bool {
	// rundll32 avoids the quoting quirks of "cmd /c start".
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", uri)
	return cmd.Start() == nil
}
