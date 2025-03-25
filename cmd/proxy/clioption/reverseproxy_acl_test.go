package clioption

import (
	"os"
	"testing"
	"time"

	"github.com/lithammer/dedent"
	"github.com/stretchr/testify/assert"
	"github.com/tingtt/oauth2rbac/internal/acl"
)

func ptr[T any](v T) *T {
	return &v
}

type loadRevProxyACLManifestTest struct {
	name    string
	rawYAML string
	want    *RevProxyACLManifest
}

var loadRevProxyACLManifestTests = []loadRevProxyACLManifestTest{
	{
		name: "",
		rawYAML: dedent.Dedent(`
			proxies:
			  - external_url: "http://www.example.com/"
			    target: "http://www:80/"
			  - external_url: "http://www.example.com/blog/"
			    target: "http://blog:80/"                    # cut the base url from request path with trailing slash "target"
			                                                #   e.g. "http://www.example.com/blog/1" proxy to "http:/blog:80/1"
			                                                # (if "target" does not have trailing slash, base url not cut.)
			  - external_url: "http://docs.example.com/"
			    target: "http://docs:80/"
			  - external_url: "http://admin.example.com/"
			    target: "http://admin:80/"
			    set_headers:
			      Remote-User: ["tingtt"]                    # MIME header key will be normalized
			                                                #  e.g.  "CUSTOM-HEADER" canonicalize to "Custom-Header"
			acl:
			  "http://www.example.com":             # External Origin
			    paths:
			      "/":
			        - methods: ["GET"]              # allow GET
			          emails: ["-"]                 # allow for anonymous use
			  "http://docs.example.com":
			    jwt_expiry_in: "3h"                 # JWT expires in 3 hour (default)
			    paths:
			      "/":
			        - methods: ["GET"]
			          emails: ["*"]                 # allow all signed-in user
			        - methods: ["*"]
			          emails: ["*@example.com"]     # allow users with a specific domain
			    roles:
			      "editor": ["*@example.com"]       # roles
			                                        #   It will be included in JWT claim.
			  "http://admin.example.com":
			    paths:
			      "/":
			        - methods: ["*"]
			          emails: ["admin@example.com"] # allow specified email user
			    roles:
			      "admin": ["admin@example.com"]
		`),
		want: &RevProxyACLManifest{
			Proxies: []proxy{
				{
					ExternalURL: "http://www.example.com/",
					Target:      "http://www:80/",
					SetHeaders:  nil,
				},
				{
					ExternalURL: "http://www.example.com/blog/",
					Target:      "http://blog:80/",
					SetHeaders:  nil,
				},
				{
					ExternalURL: "http://docs.example.com/",
					Target:      "http://docs:80/",
					SetHeaders:  nil,
				},
				{
					ExternalURL: "http://admin.example.com/",
					Target:      "http://admin:80/",
					SetHeaders: map[string][]string{
						"Remote-User": {"tingtt"},
					},
				},
			},
			ACL: acl.Pool{
				"http://www.example.com": {
					PathScopes: map[acl.Path][]acl.ScopePath{
						"/": {{
							EmailRegexes: []acl.EmailRegex{"-"},
							Methods:      []acl.Method{"GET"},
						}},
					},
					Roles:        nil,
					OriginConfig: acl.OriginConfig{},
				},
				"http://docs.example.com": {
					PathScopes: map[acl.Path][]acl.ScopePath{
						"/": {{
							EmailRegexes: []acl.EmailRegex{"*"},
							Methods:      []acl.Method{"GET"},
						}, {
							EmailRegexes: []acl.EmailRegex{"*@example.com"},
							Methods:      []acl.Method{"*"},
						}},
					},
					Roles: map[string][]acl.EmailRegex{
						"editor": {"*@example.com"},
					},
					OriginConfig: acl.OriginConfig{
						JWTExpiryIn: ptr(acl.JWTExpiryIn(time.Duration(3 * time.Hour))),
					},
				},
				"http://admin.example.com": {
					PathScopes: map[acl.Path][]acl.ScopePath{
						"/": {{
							EmailRegexes: []acl.EmailRegex{"admin@example.com"},
							Methods:      []acl.Method{"*"},
						}},
					},
					Roles: map[string][]acl.EmailRegex{
						"admin": {"admin@example.com"},
					},
					OriginConfig: acl.OriginConfig{},
				},
			},
		},
	},
}

func Test_loadRevProxyACLManifest(t *testing.T) {
	for _, tt := range loadRevProxyACLManifestTests {
		t.Run(tt.name, func(t *testing.T) {
			tmpdir := t.TempDir()
			os.WriteFile(tmpdir+"/manifest.yaml", []byte(tt.rawYAML), 0644)
			got, err := loadRevProxyACLManifest(tmpdir + "/manifest.yaml")
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
