// Command secureprojects is the SecureProjects security scanner CLI.
package main

import (
	"os"

	"github.com/secureprojects/secureprojects/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
