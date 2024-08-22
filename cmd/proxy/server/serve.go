package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"oauth2rbac/cmd/proxy/clioption"
	"oauth2rbac/internal/api/handler"
	handleroption "oauth2rbac/internal/api/handler/util/option"
)

func Serve(cliOption clioption.CLIOption) error {
	usingTLS := len(cliOption.X509KeyPairs) != 0

	server := &http.Server{
		Addr: fmt.Sprintf(":%d", cliOption.Port),
		Handler: handler.New(
			cliOption.OAuth2,
			cliOption.JWTSignKey,
			cliOption.RevProxyConfig,
			cliOption.ACL,
			handleroption.WithTLS(usingTLS),
		),
	}

	slog.Info(fmt.Sprintf("Starting HTTP Server. Listening at %s.", server.Addr))
	var err error
	if usingTLS {
		server.TLSConfig = &tls.Config{Certificates: cliOption.X509KeyPairs}
		err = server.ListenAndServeTLS("", "")
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	slog.Info("Server closed.")
	return nil
}
