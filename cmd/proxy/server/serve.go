package server

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"oauth2rbac/cmd/proxy/clioption"
	"oauth2rbac/internal/api/handler"
)

func Serve(cliOption clioption.CLIOption) error {
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", cliOption.Port),
		Handler: handler.New(
			cliOption.OAuth2,
			cliOption.JWTSignKey,
			cliOption.RevProxyConfig,
			cliOption.ACL,
		),
	}

	if /* TLS cert/key specified */ len(cliOption.X509KeyPairs) != 0 {
		server.TLSConfig = &tls.Config{Certificates: cliOption.X509KeyPairs}
	}

	slog.Info(fmt.Sprintf("Starting HTTP Server. Listening at %s.", server.Addr))
	var err error
	if /* TLS cert/key specified */ len(cliOption.X509KeyPairs) != 0 {
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
