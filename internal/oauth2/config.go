package oauth2

import (
	"context"
	"crypto/rand"
	"encoding/base64"

	"github.com/tingtt/oauth2rbac/internal/acl"

	"golang.org/x/oauth2"
)

type Config = oauth2.Config

type Service interface {
	Config() Config
	AuthCodeURL(redirectUrl string) string
	Exchange(ctx context.Context, code string, redirectURL string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	GetEmail(ctx context.Context, token *oauth2.Token) (emails []acl.Email, err error)
}

func New(
	c *oauth2.Config,
	getEmailFunc func(ctx context.Context, config oauth2.Config, token *oauth2.Token) (emails []string, err error),
) Service {
	return &config{value: c, getEmailFunc: getEmailFunc}
}

type config struct {
	value        *oauth2.Config
	getEmailFunc func(ctx context.Context, config oauth2.Config, token *oauth2.Token) (emails []string, err error)
}

func (c *config) Config() Config {
	return *c.value
}

func (c *config) AuthCodeURL(redirectURL string) string {
	config := c.Config() /* copy as base config */
	config.RedirectURL = redirectURL
	return config.AuthCodeURL(state(), oauth2.AccessTypeOffline, oauth2.ApprovalForce)
}

func state() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (c *config) Exchange(ctx context.Context, code string, redirectURL string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	config := c.Config() /* copy as base config */
	config.RedirectURL = redirectURL
	return config.Exchange(ctx, code, opts...)
}

func (c *config) GetEmail(ctx context.Context, token *oauth2.Token) ([]acl.Email, error) {
	return c.getEmailFunc(ctx, *c.value, token)
}
