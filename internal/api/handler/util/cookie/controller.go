package cookieutil

import (
	"net/http"
	logutil "oauth2rbac/internal/api/handler/util/log"
	"time"
)

const (
	COOKIE_KEY_REDIRECT_URL_FOR_AFTER_LOGIN = "redirect_after_login"
)

type Controller interface {
	SetRedirectURLForAfterLogin(res *logutil.CustomResponseWriter, reqURL string)
	SetJWT(rw http.ResponseWriter, jwt string)
}

func NewController(secure bool) Controller {
	return &controller{}
}

type controller struct {
	useSecure bool
}

func (c *controller) SetRedirectURLForAfterLogin(res *logutil.CustomResponseWriter, reqURL string) {
	http.SetCookie(res, &http.Cookie{
		Name:     COOKIE_KEY_REDIRECT_URL_FOR_AFTER_LOGIN,
		Value:    reqURL,
		Path:     "/",
		Domain:   "",
		MaxAge:   int(time.Hour / time.Second),
		Secure:   c.useSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // use Lax mode (https://issues.chromium.org/issues/40508226)
	})
}

func (c *controller) SetJWT(rw http.ResponseWriter, jwt string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     "jwt",
		Value:    jwt,
		Path:     "/",
		Domain:   "",
		MaxAge:   int(time.Hour / time.Second),
		Secure:   c.useSecure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}
