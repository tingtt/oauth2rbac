package main

import (
	"log/slog"
	"oauth2rbac/cmd/proxy/clioption"
	"oauth2rbac/cmd/proxy/server"
	"os"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
		return
	}
}

func run() error {
	cliOption, err := clioption.Load()
	if err != nil {
		return err
	}

	return server.Serve(cliOption)
}
