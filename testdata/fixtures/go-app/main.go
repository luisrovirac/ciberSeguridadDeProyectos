package main

import (
	"crypto/tls"
	"net/http"
	"os/exec"

	_ "golang.org/x/text/language"
)

func main() {
	// Intentionally insecure for testing.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	_ = &http.Client{Transport: tr}
	_ = exec.Command("sh", "-c", "echo hello").Run()
}
