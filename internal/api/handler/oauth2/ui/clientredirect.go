package ui

import (
	"maragu.dev/gomponents"
	"maragu.dev/gomponents/html"
)

func ClientSideRedirect(location string) gomponents.Node {
	return layout(
		html.Div(
			html.P(
				gomponents.Text("If you are not redirected automatically, follow this "),
				html.A(gomponents.Attr("href", location), gomponents.Text("link")),
				gomponents.Text("."),
			),
			html.Script(gomponents.Rawf("window.location.href = \"%s\";", location)),
		),
	)
}
