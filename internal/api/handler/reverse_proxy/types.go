package reverseproxy

type Config struct {
	Proxies []Proxy
}

type Proxy struct {
	ExternalURL string
	Target      Target
	SetHeaders  map[string][]string
}

type Target struct {
	URL string
}
