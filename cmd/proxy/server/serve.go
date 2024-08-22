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
	handler, err := handler.New(cliOption.OAuth2, cliOption.RevProxyConfig,
		handleroption.WithJWTAuth(cliOption.JWTSignKey),
		handleroption.WithSecureCookie(cliOption.UseSecureCookie),
		handleroption.WithScope(cliOption.ACL),
	)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cliOption.Port),
		Handler: handler,
	}

	if /* TLS cert/key specified */ len(cliOption.X509KeyPairs) != 0 {
		server.TLSConfig = &tls.Config{Certificates: cliOption.X509KeyPairs}
		slog.Info(fmt.Sprintf("Starting HTTPS Server. Listening at %s.", server.Addr))
		err = server.ListenAndServeTLS("", "")
	} else {
		slog.Info(fmt.Sprintf("Starting HTTP Server. Listening at %s.", server.Addr))
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	slog.Info("Server closed.")
	return nil
}
