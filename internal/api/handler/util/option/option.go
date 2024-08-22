package handleroption

import "oauth2rbac/internal/util/options"

type Option struct {
	UsingTLS bool
}

type Applier = options.Applier[Option]

func WithTLS(usingTLS bool) Applier {
	return func(o *Option) { o.UsingTLS = usingTLS }
}
