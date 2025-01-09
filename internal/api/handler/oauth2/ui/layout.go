package ui

import (
	"github.com/lithammer/dedent"
	"maragu.dev/gomponents"
	"maragu.dev/gomponents/html"
)

func Layout(child gomponents.Node) gomponents.Node {
	return html.Doctype(html.HTML(
		html.StyleEl(gomponents.Text(dedent.Dedent(`
			:root {
				--background: #C7C7C7;
				--foreground: #151B22;
				--base: #f2f2f2;
			}

			@media (prefers-color-scheme: dark) {
				:root {
					--background: #151B22;
					--foreground: #f2f2f2;
					--base: #0a0a0a;
				}
			}
		`))),
		html.Head(
			html.Meta(
				html.Name("viewport"),
				html.Content("width=device-width, initial-scale=1"),
			),
		),
		html.Body(
			html.Style(dedent.Dedent(`
				color: var(--foreground);
				background: var(--background);
			`)),
			child,
		),
	))
}
