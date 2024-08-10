package oauth2

import (
	"context"
	"oauth2rbac/internal/oauth2/github"
	"oauth2rbac/internal/oauth2/google"

	"golang.org/x/oauth2"
)

type Provider struct {
	Endpoint     oauth2.Endpoint
	Scopes       []string
	GetEmailFunc func(ctx context.Context, config Config, token *oauth2.Token) (emails []string, err error)
}

var Providers = map[string]Provider{
	"google": {
		Endpoint:     google.Endpoint,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		GetEmailFunc: google.GetEmailFunc,
	},
	"github": {
		Endpoint:     github.Endpoint,
		Scopes:       []string{"user:email"},
		GetEmailFunc: github.GetEmailFunc,
	},
}
