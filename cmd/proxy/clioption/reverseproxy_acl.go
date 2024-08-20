package clioption

import (
	"fmt"
	"net/url"
	"oauth2rbac/internal/acl"
	reverseproxy "oauth2rbac/internal/api/handler/reverse_proxy"
	"oauth2rbac/internal/util/slices"
	"os"

	"gopkg.in/yaml.v3"
)

type RevProxyACLManifest struct {
	Proxies []proxy  `yaml:"proxies"`
	ACL     acl.Pool `yaml:"acl"`
}

type proxy struct {
	ExternalURL string            `yaml:"external_url"`
	Target      string            `yaml:"target"`
	SetHeaders  map[string]string `yaml:"set_headers"`
}

func RevProxyACL(yamlFilePath string) (reverseproxy.Config, acl.Pool, error) {
	manifest, err := loadRevProxyACLManifest(yamlFilePath)
	if err != nil {
		return reverseproxy.Config{}, nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	proxies, err := slices.MapE(manifest.Proxies, func(proxy proxy) (reverseproxy.Proxy, error) {
		fromURL, err := url.Parse(proxy.ExternalURL)
		if err != nil {
			return reverseproxy.Proxy{}, err
		}

		targetURL, err := url.Parse(proxy.Target)
		if err != nil {
			return reverseproxy.Proxy{}, err
		}

		return reverseproxy.Proxy{
			ExternalURL: fromURL,
			Target:      reverseproxy.Host{URL: targetURL},
			SetHeaders:  proxy.SetHeaders,
		}, nil
	})
	if err != nil {
		return reverseproxy.Config{}, nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	return reverseproxy.Config{Proxies: proxies}, manifest.ACL, nil
}

// Example usage:
//
//	```yaml
//	proxies:
//	  - external_url: "http://www.example.com/"
//	    target: "http://www:80/"
//	  - external_url: "http://docs.example.com/"
//	    target: "http://docs:80/"
//	  - external_url: "http://admin.example.com/"
//	    target: "http://admin:80/"
//	acl:
//	  "-":                             # public
//	    - "http://www.example.com/"
//	  "*":                             # allow all signed-in user
//	    - "http://docs.example.com/"
//	  "*@gmail.com":                   # allow all gmail user
//	    - "http://docs.example.com/"
//	  "example@gmail.com":             # allow specified gmail user
//	    - "http://admin.example.com/"
//	```
func loadRevProxyACLManifest(yamlFilePath string) (*RevProxyACLManifest, error) {
	data, err := os.ReadFile(yamlFilePath)
	if err != nil {
		return nil, err
	}

	var manifest RevProxyACLManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}
