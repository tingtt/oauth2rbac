package oauth2

import (
	"fmt"
	"net/http"
	"oauth2rbac/internal/oauth2"

	"github.com/go-xmlfmt/xmlfmt"
)

func (h *Handler) SelectProvider(w http.ResponseWriter, r *http.Request) {
	htmlFormat := `<!DOCTYPE html><html><body>%s</body></html>`
	body := ""
	for providerName := range oauth2.Providers {
		body += fmt.Sprintf(`<div><a href="/.auth/%s/login?%s">%s</a></div>`, providerName, r.URL.RawQuery, providerName)
	}
	w.Write([]byte(xmlfmt.FormatXML(fmt.Sprintf(htmlFormat, body), "\t", "  ")))
}
