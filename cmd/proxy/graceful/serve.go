package graceful

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"oauth2rbac/cmd/proxy/clioption"
	"oauth2rbac/internal/api/handler"
	"os"
	"os/signal"
	"syscall"
	"time"
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

	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for syscall signals for process to interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sig

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, _ := context.WithTimeout(serverCtx, 30*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if shutdownCtx.Err() == context.DeadlineExceeded {
				log.Fatal("graceful shutdown timed out.. forcing exit.")
			}
		}()

		// Trigger graceful shutdown
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		serverStopCtx()
	}()

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

	<-serverCtx.Done()
	slog.Info("Server closed.")
	return nil
}
