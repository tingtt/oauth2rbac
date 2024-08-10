package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"oauth2rbac/internal/api/handler"
	"oauth2rbac/internal/oauth2"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/pflag"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
		return
	}
}

func run() error {
	cliOption, err := getCLIOption()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cliOption.Port),
		Handler: handler.New(cliOption.OAuth2),
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
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	<-serverCtx.Done()
	slog.Info("Server closed.")
	return nil
}

type cliOption struct {
	Port   uint16
	OAuth2 handler.Oauth2Config
}

func getCLIOption() (cliOption, error) {
	port := pflag.Uint16("port", 8080, "Port to listen")
	redirectOrigin := pflag.String("origin", "http://localhost:8080", "Origin")
	oauth2Clients := pflag.StringArray("oauth2-client", nil, "Google OAuth2 Client ID (format: `<ProviderName>;<ClientID>;<ClientSecret>`)")
	pflag.Parse()

	oauth2Config := handler.Oauth2Config{}
	for _, c := range *oauth2Clients {
		client := strings.Split(c, ";")
		if len(client) != 3 {
			return cliOption{}, errors.New("invalid format CLI option `--oauth2-client` given")
		}
		providerName, clientId, clientSecret := client[0], client[1], client[2]

		provider, supported := oauth2.Providers[providerName]
		if !supported {
			return cliOption{}, fmt.Errorf("oauth2 provider `%s` is not supported", providerName)
		}

		// RedirectURL: `<origin>/.auth/<probider>/callback`
		redirectURL := path.Join(*redirectOrigin, ".auth", providerName, "callback")

		oauth2Config[providerName] = oauth2.New(&oauth2.Config{
			RedirectURL:  redirectURL,
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Scopes:       nil,
			Endpoint:     provider.Endpoint,
		}, provider.GetEmailFunc)
	}
	if len(oauth2Config) == 0 {
		return cliOption{}, errors.New("CLI option `--oauth2-client` is required")
	}

	return cliOption{
		Port:   *port,
		OAuth2: oauth2Config,
	}, nil
}
