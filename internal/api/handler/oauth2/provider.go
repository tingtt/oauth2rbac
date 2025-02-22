package oauth2handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"oauth2rbac/internal/api/handler/oauth2/ui"
	logutil "oauth2rbac/internal/api/handler/util/log"
	urlutil "oauth2rbac/internal/api/handler/util/url"
)

func (h *handler) SelectProvider(rw http.ResponseWriter, req *http.Request) {
	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	res, logInfo := logutil.InfoLogger(reqURL, req.Method, rw, req)

	html := ui.ProviderListUI(req.URL.RawQuery)
	err := html.Render(res)
	if err != nil {
		slog.Error(fmt.Errorf("failed render html: %w", err).Error())
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	res.WriteHeader(http.StatusOK)

	logInfo("")
}
