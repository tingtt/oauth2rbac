package handler

import "oauth2rbac/internal/oauth2"

type handler struct {
	config config
}

type config struct {
	oauth2 Oauth2Config
}

type Oauth2Config map[string]oauth2.Service
