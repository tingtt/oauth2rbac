package acl

type Pool map[Email][]Scope

type Email string
type Scope string
