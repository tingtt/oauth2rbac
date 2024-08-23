package oauth2handler

import (
	"fmt"
	"net/http"
	logutil "oauth2rbac/internal/api/handler/util/log"
	urlutil "oauth2rbac/internal/api/handler/util/url"
	"oauth2rbac/internal/oauth2"

	"github.com/go-xmlfmt/xmlfmt"
)

func (h *handler) SelectProvider(rw http.ResponseWriter, req *http.Request) {
	reqURL := urlutil.RequestURL(*req.URL, urlutil.WithRequest(req), urlutil.WithXForwardedHeaders(req.Header))
	res, logInfo := logutil.InfoLogger(reqURL, req.Method, rw, req)

	htmlFormat := `<!DOCTYPE html><html><body>%s</body></html>`
	body := ""
	for providerName := range oauth2.Providers {
		body += fmt.Sprintf(`<div><a href="/.auth/%s/login?%s">%s</a></div>`, providerName, req.URL.RawQuery, providerName)
	}
	res.Write([]byte(xmlfmt.FormatXML(fmt.Sprintf(htmlFormat, body), "\t", "  ")))
	res.WriteHeader(http.StatusOK)

	logInfo("")
}
