package ui

import (
	"testing"
)

func Test_providerNamesWithDisplayName(t *testing.T) {
	t.Parallel()

	t.Run("Icon is not nil", func(t *testing.T) {
		t.Parallel()
		got := providerNamesWithDisplayName()
		for _, provider := range got {
			if provider.Icon == nil {
				t.Errorf("provider.Icon is nil (provider: %v)", provider.Name)
			}
		}
	})
}
