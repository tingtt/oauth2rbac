package acl

import (
	"reflect"
	"testing"
)

func TestScopeOrigin_LoginRequired(t *testing.T) {
	type fields struct {
		PathScopes   map[Path][]ScopePath
		Roles        map[string][]EmailRegex
		OriginConfig OriginConfig
	}
	type args struct {
		path   string
		method string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "anonymous user allowed",
			fields: fields{
				PathScopes: map[Path][]ScopePath{
					"/": {
						{
							EmailRegexes: []EmailRegex{"-"},
							Methods:      []Method{"GET"},
						},
						{
							EmailRegexes: []EmailRegex{"admin@example.test"},
							Methods:      []Method{"*"},
						},
					},
				},
				Roles:        map[string][]EmailRegex{},
				OriginConfig: OriginConfig{},
			},
			args: args{"/", "GET"},
			want: false,
		},
		{
			name: "login required",
			fields: fields{
				PathScopes: map[Path][]ScopePath{
					"/": {
						{
							EmailRegexes: []EmailRegex{"-"},
							Methods:      []Method{"GET"},
						},
						{
							EmailRegexes: []EmailRegex{"admin@example.test"},
							Methods:      []Method{"*"},
						},
					},
				},
				Roles:        map[string][]EmailRegex{},
				OriginConfig: OriginConfig{},
			},
			args: args{"/", "POST"},
			want: true,
		},
		{
			name: "login required",
			fields: fields{
				PathScopes: map[Path][]ScopePath{
					"/": {
						{
							EmailRegexes: []EmailRegex{"*"},
							Methods:      []Method{"GET"},
						},
					},
				},
				Roles:        map[string][]EmailRegex{},
				OriginConfig: OriginConfig{},
			},
			args: args{"/", "GET"},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := ScopeOrigin{
				PathScopes:   tt.fields.PathScopes,
				Roles:        tt.fields.Roles,
				OriginConfig: tt.fields.OriginConfig,
			}
			if got := scope.LoginRequired(tt.args.path, tt.args.method); got != tt.want {
				t.Errorf("ScopeOrigin.LoginRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScopeOrigin_AllowedRoles(t *testing.T) {
	type fields struct {
		PathScopes   map[Path][]ScopePath
		Roles        map[string][]EmailRegex
		OriginConfig OriginConfig
	}
	type args struct {
		email string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []string
	}{
		{
			name: "no roles",
			fields: fields{
				PathScopes: map[Path][]ScopePath{
					"/": {
						{
							EmailRegexes: []EmailRegex{"-"},
							Methods:      []Method{"GET"},
						},
					},
				},
				Roles: map[string][]EmailRegex{
					"unused": {"unused@example.test"},
				},
				OriginConfig: OriginConfig{},
			},
			args: args{"admin@example.test"},
			want: []string{},
		},
		{
			name: "role for specific email",
			fields: fields{
				PathScopes: map[Path][]ScopePath{
					"/": {
						{
							EmailRegexes: []EmailRegex{"*@example.test"},
							Methods:      []Method{"*"},
						},
					},
				},
				Roles: map[string][]EmailRegex{
					"admin": {"admin@example.test"},
				},
				OriginConfig: OriginConfig{},
			},
			args: args{"admin@example.test"},
			want: []string{"admin"},
		},
		{
			name: "role for email regex",
			fields: fields{
				PathScopes: map[Path][]ScopePath{
					"/": {
						{
							EmailRegexes: []EmailRegex{"*@example.test"},
							Methods:      []Method{"*"},
						},
					},
				},
				Roles: map[string][]EmailRegex{
					"admin": {"admin@example.test"},
					"user":  {"*@example.test"},
				},
				OriginConfig: OriginConfig{},
			},
			args: args{"admin@example.test"},
			want: []string{"admin", "user"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := ScopeOrigin{
				PathScopes:   tt.fields.PathScopes,
				Roles:        tt.fields.Roles,
				OriginConfig: tt.fields.OriginConfig,
			}
			if got := scope.AllowedRoles(tt.args.email); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ScopeOrigin.AllowedRoles() = %v, want %v", got, tt.want)
			}
		})
	}
}
