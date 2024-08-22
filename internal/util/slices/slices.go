package slices

func Map[T1, T2 any](slice []T1, yield func(T1) T2) []T2 {
	newSlice := make([]T2, 0, len(slice))
	for _, value := range slice {
		newSlice = append(newSlice, yield(value))
	}
	return newSlice
}

func MapE[T1, T2 any](slice []T1, yield func(T1) (T2, error)) ([]T2, error) {
	newSlice := make([]T2, 0, len(slice))
	for _, value := range slice {
		newValue, err := yield(value)
		if err != nil {
			return nil, err
		}
		newSlice = append(newSlice, newValue)
	}
	return newSlice, nil
}

func Some[T any](slice []T, yield func(T) bool) bool {
	for _, value := range slice {
		if yield(value) {
			return true
		}
	}
	return false
}

func Find[T any](slice []T, yield func(T) bool) *T {
	for _, value := range slice {
		if yield(value) {
			return &value
		}
	}
	return nil
}
