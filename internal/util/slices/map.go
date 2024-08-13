package slices

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
