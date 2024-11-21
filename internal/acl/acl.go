package acl

type Pool map[EmailRegex][]Scope

type EmailRegex = string
type Email = string
type Scope struct {
	ExternalURL string   `yaml:"external_url"`
	Methods     []string `yaml:"methods"`
}
