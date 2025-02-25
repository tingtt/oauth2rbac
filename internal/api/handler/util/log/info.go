package logutil

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	urlutil "github.com/tingtt/oauth2rbac/internal/api/handler/util/url"
	"github.com/tingtt/oauth2rbac/internal/util/slices"
)

func InfoLogger(reqURL url.URL, method string, rw http.ResponseWriter, req *http.Request) (
	*CustomResponseWriter,
	func(msg string, args ...slog.Attr),
) {
	res := &CustomResponseWriter{ResponseWriter: rw}

	xForwardedFor := urlutil.InspectXForwardedFor(req.Header)
	requestInfo := fmt.Sprintf("%s %s", method, reqURL.String())

	return res, func(msg string, _args ...slog.Attr) {
		args := []any{
			slog.String("remote_addr", req.RemoteAddr),
			slog.String("http_x_forwarded_for", xForwardedFor),
			slog.Int("status", res.StatusCode),
		}
		if msg != "" {
			args = append(args, slog.String("msg", msg))
		}
		args = append(args, slices.Map(_args, func(a slog.Attr) any { return a })...)
		slog.Info(requestInfo, args...)
	}
}
