package ui

import (
	"fmt"
	"slices"

	"github.com/tingtt/oauth2rbac/internal/api/handler/oauth2/ui/assets"
	"github.com/tingtt/oauth2rbac/internal/oauth2"

	"github.com/lithammer/dedent"
	"maragu.dev/gomponents"
	"maragu.dev/gomponents/html"
)

func ProviderListUI(rawQuery string) gomponents.Node {
	return layout(html.Div(
		html.Style(dedent.Dedent(`
			max-width: 320px;
			margin: 40px auto;
			background: var(--base);
			border-radius: 16px;
			padding: 20px 32px;
		`)),
		html.Div(
			html.Style(dedent.Dedent(`
				margin: 20px 4px;
				font-size: 2rem;
				font-weight: bold;
				overflow: hidden;
				white-space: nowrap;
			`)),
			html.Div(gomponents.Text("Sign in to ")),
			html.Div(html.ID("header")),
			html.Script(
				gomponents.Raw(dedent.Dedent(`
					document.getElementById("header").innerText = location.host;
				`)),
			),
		),
		html.Div(
			html.Style(dedent.Dedent(`
				display: grid;
				gap: 16px;
			`)),
			html.StyleEl(gomponents.Text(dedent.Dedent(`
				.providerLinkButton {
					display: flex;
					align-items: center;
					gap: 8px;
					justify-content: space-between;
					background: var(--background);
					color: var(--foreground);
					border-radius: 8px;
					padding: 12px 16px;
					text-decoration: none;
				}
				.providerLinkButton:hover {
					outline: 1px solid var(--foreground);
				}
			`))),
			gomponents.Map(providerNamesWithDisplayName(),
				func(provider Provider) gomponents.Node {
					url := fmt.Sprintf("/.auth/%s/login?%s", provider.Name, rawQuery)
					return html.Div(html.A(
						html.Class("providerLinkButton"),
						html.Href(url),
						html.Div(gomponents.Text(
							fmt.Sprintf("Sign in with %s", provider.DisplayName),
						)),
						provider.Icon(24, 24),
					))
				},
			),
		),
		html.Div(
			html.Style("margin-top: 20px; margin-left: 4px;"),
			html.A(
				html.Style(dedent.Dedent(`
					display: flex;
					align-items: center;
					gap: 8px;
					border-radius: 8px;
					text-decoration: none;
					color: var(--foreground);
				`)),
				assets.SVGGitHub(24, 24),
				html.Href("https://github.com/tingtt/oauth2rbac"),
				html.Target("_blank"),
				html.P(gomponents.Text("tingtt/oauth2rbac")),
			),
		),
	))
}

type IconFunc func(width, height int) gomponents.Node

type Provider struct {
	Name, DisplayName string
	Icon              IconFunc
}

func providerNamesWithDisplayName() []Provider {
	providerNames := oauth2.ProviderNames()
	slices.Sort(providerNames)
	providerNamesWithDisplayName := make([]Provider, 0, len(providerNames))
	for i, providerName := range providerNames {
		provider := oauth2.Providers[providerName]
		providerNamesWithDisplayName = append(providerNamesWithDisplayName, Provider{
			Name:        providerName,
			DisplayName: provider.DisplayName,
		})
		if iconFunc, ok := ProviderIcons[providerName]; ok {
			providerNamesWithDisplayName[i].Icon = iconFunc
		}
	}
	return providerNamesWithDisplayName
}

var ProviderIcons = map[string]IconFunc{
	"github": assets.SVGGitHub,
	"google": assets.SVGGoogle,
}
