package oauth2

import (
	"context"

	"github.com/tingtt/oauth2rbac/internal/oauth2/github"
	"github.com/tingtt/oauth2rbac/internal/oauth2/google"

	"golang.org/x/oauth2"
)

type Provider struct {
	Endpoint        oauth2.Endpoint
	Scopes          []string
	GetUserInfoFunc func(ctx context.Context, config Config, token *oauth2.Token) (username string, emails []string, err error)
	DisplayName     string
}

var Providers = map[string]Provider{
	"google": {
		Endpoint: google.Endpoint,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		GetUserInfoFunc: google.GetUserInfoFunc,
		DisplayName:     "Google",
	},
	"github": {
		Endpoint: github.Endpoint,
		Scopes: []string{
			"user:email",
			"read:user",
		},
		GetUserInfoFunc: github.GetUserInfoFunc,
		DisplayName:     "GitHub",
	},
}

func ProviderNames() []string {
	providerNames := make([]string, 0, len(Providers))
	for providerName := range Providers {
		providerNames = append(providerNames, providerName)
	}
	return providerNames
}
