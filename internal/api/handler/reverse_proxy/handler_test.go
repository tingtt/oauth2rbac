package reverseproxy

import (
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"oauth2rbac/internal/util/slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewReverseProxyHandler(t *testing.T) {
	t.Parallel()

	config := Config{Proxies: []Proxy{
		{ExternalURL: "http://example.com/"},
		{ExternalURL: "http://example.com/base/"},
		{ExternalURL: "http://example.com/-/healthz"},
	}}

	t.Run("proxyMatchKeys may sorted descending order by number of characters", func(t *testing.T) {
		t.Parallel()
		h := NewReverseProxyHandler(config, nil, nil)

		assert.Equal(t, h.proxyMatchKeys, []string{
			"http://example.com/-/healthz",
			"http://example.com/base/",
			"http://example.com/",
		})

		proxyMatchKeys := make([]string, 0, len(h.proxies))
		for k := range h.proxies {
			proxyMatchKeys = append(proxyMatchKeys, k)
		}
		assert.ElementsMatch(t, h.proxyMatchKeys, proxyMatchKeys)
	})
}

type MockResponseWriter struct {
	mock.Mock
}

func (m *MockResponseWriter) Header() http.Header {
	return http.Header{}
}
func (m *MockResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}
func (m *MockResponseWriter) WriteHeader(statusCode int) {
	m.Called(statusCode)
}

type MockTransport struct {
	mock.Mock
}

func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func Test_handler_matchProxy(t *testing.T) {
	t.Parallel()

	type arg struct {
		method string
		url    string
	}
	type wantProxy struct {
		url string
	}
	type test[T any] struct {
		name   string
		config Config
		req    arg
		want   T
	}

	t.Run("may match on the same origin and the longest path", func(t *testing.T) {
		t.Parallel()

		config := Config{Proxies: []Proxy{
			{ExternalURL: "https://example.com/", Target: Target{"http://web:80"}},
			{ExternalURL: "https://example.com/api/", Target: Target{"http://app:3000"}},
			{ExternalURL: "https://example.com/longbasepath/", Target: Target{"http://longesthost:3000"}},
		}}
		tests := []test[wantProxy]{
			{
				config: config,
				req:    arg{http.MethodGet, "https://example.com/path/to/proxy"},
				want:   wantProxy{"http://web:80/path/to/proxy"},
			},
			{
				config: config,
				req:    arg{http.MethodGet, "https://example.com/api/endpoint"},
				want:   wantProxy{"http://app:3000/api/endpoint"},
			},
			{
				config: config,
				req:    arg{http.MethodGet, "https://example.com/longbasepath/"},
				want:   wantProxy{"http://longesthost:3000/longbasepath/"},
			},
		}

		for i, tt := range tests {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()

				req, wantRequestURI, resFixedReturn := func(_req arg, _want wantProxy) (*http.Request, func(req *http.Request) bool, *http.Response) {
					reqURL, _ := url.Parse(_req.url)
					assert.NotNil(t, reqURL)
					req := http.Request{
						Method: _req.method,
						URL:    reqURL,
					}
					match := func(req *http.Request) bool {
						assert.Equal(t, _req.method, req.Method)
						assert.Equal(t, _want.url, req.URL.String())
						return true
					}
					res := http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader("")),
					}
					return &req, match, &res
				}(tt.req, tt.want)

				proxy, mockTransport := func(config Config, reqURL url.URL) (*httputil.ReverseProxy, *MockTransport) {
					proxy := NewReverseProxyHandler(config, nil, nil).matchProxy(reqURL)
					assert.NotNil(t, proxy)
					mockTransport := new(MockTransport)
					proxy.Transport = mockTransport
					return proxy, mockTransport
				}(tt.config, *req.URL)
				rw := new(MockResponseWriter)

				mockTransport.On("RoundTrip", mock.MatchedBy(wantRequestURI)).Return(resFixedReturn, nil)
				rw.On("WriteHeader", resFixedReturn.StatusCode)

				proxy.ServeHTTP(rw, req)
			})
		}
	})

	t.Run("matched proxy director may rewrite URL (if target URL has a trailing slash, cut the base url)", func(t *testing.T) {
		t.Parallel()

		config := Config{Proxies: []Proxy{
			{ExternalURL: "https://example.com/api/", Target: Target{"http://app1:3000/"}},
			{ExternalURL: "https://example.com/api/with/baseurl/", Target: Target{"http://app2:3000"}},
		}}
		tests := []test[wantProxy]{
			{
				name:   "base url will cut off",
				config: config,
				req:    arg{http.MethodGet, "https://example.com/api/path/to/proxy"},
				want:   wantProxy{"http://app1:3000/path/to/proxy"},
			},
			{
				name:   "base url will remain",
				config: config,
				req:    arg{http.MethodGet, "https://example.com/api/with/baseurl/path/to/proxy"},
				want:   wantProxy{"http://app2:3000/api/with/baseurl/path/to/proxy"},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				reqURL, _ := url.Parse(tt.req.url)

				proxy := NewReverseProxyHandler(tt.config, nil, nil).matchProxy(*reqURL)
				assert.NotNil(t, proxy)
				proxy.Director(&http.Request{
					Method:     tt.req.method,
					URL:        reqURL,
					Header:     http.Header{},
					Body:       io.NopCloser(strings.NewReader("")),
					RequestURI: reqURL.RequestURI(),
				})
				assert.Equal(t, tt.want.url, reqURL.String())
			})
		}
	})

	t.Run("proxy director may add headers", func(t *testing.T) {
		t.Parallel()

		type wantProxyWithHeader struct {
			url     string
			headers http.Header
		}
		matchTargetURL := func(targetURL string) func(proxy Proxy) bool {
			return func(proxy Proxy) bool { return proxy.Target.URL == targetURL }
		}

		config := Config{Proxies: []Proxy{
			{
				ExternalURL: "https://example.com/",
				Target:      Target{"http://web:80"},
				SetHeaders:  map[string][]string{},
			},
			{
				ExternalURL: "https://example.com/api/",
				Target:      Target{"http://app:3000"},
				SetHeaders:  map[string][]string{"App-Api-Key": {"key..."}},
			},
			{
				ExternalURL: "https://example.com/longbasepath/",
				Target:      Target{"http://longesthost:3000"},
				SetHeaders:  map[string][]string{"X-Custom-Header": {"proxied"}},
			},
		}}
		tests := []test[wantProxyWithHeader]{
			{
				config: config,
				req:    arg{http.MethodGet, "https://example.com/path/to/proxy"},
				want: wantProxyWithHeader{
					"http://web:80/path/to/proxy",
					slices.Find(config.Proxies, matchTargetURL("http://web:80")).SetHeaders,
				},
			},
			{
				config: config,
				req:    arg{http.MethodGet, "https://example.com/api/endpoint"},
				want: wantProxyWithHeader{
					"http://app:3000/api/endpoint",
					slices.Find(config.Proxies, matchTargetURL("http://app:3000")).SetHeaders,
				},
			},
			{
				config: config,
				req:    arg{http.MethodGet, "https://example.com/longbasepath/"},
				want: wantProxyWithHeader{
					"http://longesthost:3000/longbasepath/",
					slices.Find(config.Proxies, matchTargetURL("http://longesthost:3000")).SetHeaders,
				},
			},
		}

		for i, tt := range tests {
			t.Run(strconv.Itoa(i), func(t *testing.T) {
				t.Parallel()

				reqURL, _ := url.Parse(tt.req.url)

				proxy := NewReverseProxyHandler(tt.config, nil, nil).matchProxy(*reqURL)
				assert.NotNil(t, proxy)
				req := &http.Request{
					Method:     tt.req.method,
					URL:        reqURL,
					Header:     http.Header{},
					Body:       io.NopCloser(strings.NewReader("")),
					RequestURI: reqURL.RequestURI(),
				}
				proxy.Director(req)
				assert.Equal(t, tt.want.url, reqURL.String())
				assert.Equal(t, tt.want.headers, req.Header)
			})
		}
	})
}
