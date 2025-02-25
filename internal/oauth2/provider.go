package oauth2

import (
	"context"

	"github.com/tingtt/oauth2rbac/internal/oauth2/github"
	"github.com/tingtt/oauth2rbac/internal/oauth2/google"

	"golang.org/x/oauth2"
)

type Provider struct {
	Endpoint     oauth2.Endpoint
	Scopes       []string
	GetEmailFunc func(ctx context.Context, config Config, token *oauth2.Token) (emails []string, err error)
	DisplayName  string
}

var Providers = map[string]Provider{
	"google": {
		Endpoint:     google.Endpoint,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		GetEmailFunc: google.GetEmailFunc,
		DisplayName:  "Google",
	},
	"github": {
		Endpoint:     github.Endpoint,
		Scopes:       []string{"user:email"},
		GetEmailFunc: github.GetEmailFunc,
		DisplayName:  "GitHub",
	},
}

func ProviderNames() []string {
	providerNames := make([]string, 0, len(Providers))
	for providerName := range Providers {
		providerNames = append(providerNames, providerName)
	}
	return providerNames
}
