package options

func Create[T any](options ...Applier[T]) *T {
	option := new(T)
	for _, apply := range options {
		apply(option)
	}
	return option
}

type Applier[T any] func(*T)
