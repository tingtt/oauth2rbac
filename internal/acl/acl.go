package acl

type Pool map[EmailRegex][]Scope

type EmailRegex = string
type Email = string
type Scope = string
