// Command secureprojects is the SecureProjects security scanner CLI.
package main

import (
	"os"

	"github.com/luisrovirac/ciberSeguridadDeProyectos/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
