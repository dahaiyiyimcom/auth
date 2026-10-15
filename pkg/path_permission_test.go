package pkg

import (
	"reflect"
	"testing"
)

// iterations is how many times each case is matched. Go randomizes map
// iteration order, so a single run could pass by luck with an order-dependent
// implementation.
const iterations = 200

func TestMatchPathWithPermission(t *testing.T) {
	permissions := map[string][]int{
		"/v1/product":                   {1, 2, 3},
		"/v1/product/list":              {1, 2, 3},
		"/v1/product/list/search":       {1, 2, 3},
		"/v1/product/unapproved":        {1, 2, 3},
		"/v1/product/image":             {1, 2, 3},
		"/v1/product/:id":               {1, 3},
		"/v1/product/:id/images":        {1, 4},
		"/v1/product/detail/:id":        {1, 5},
		"/v1/product/detail/unapproved": {1, 6},
		"/v1/shop/:shopId/orders":       {1, 7},
		"/v1/shop/main/:section":        {1, 8},
	}

	tests := []struct {
		name      string
		path      string
		want      []int
		wantFound bool
	}{
		{"static wins over param", "/v1/product/list", []int{1, 2, 3}, true},
		{"static wins over param (unapproved)", "/v1/product/unapproved", []int{1, 2, 3}, true},
		{"static wins over param (image)", "/v1/product/image", []int{1, 2, 3}, true},
		{"param still matches other values", "/v1/product/123", []int{1, 3}, true},
		{"param followed by static segment", "/v1/product/123/images", []int{1, 4}, true},
		{"static wins at deeper segment", "/v1/product/detail/unapproved", []int{1, 6}, true},
		{"param at deeper segment", "/v1/product/detail/42", []int{1, 5}, true},
		{"earliest static segment wins", "/v1/shop/main/orders", []int{1, 8}, true},
		{"trailing slash is ignored", "/v1/product/list/", []int{1, 2, 3}, true},
		{"segment count mismatch", "/v1/product/list/search/extra", nil, false},
		{"unknown path", "/v1/unknown", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < iterations; i++ {
				got, found := MatchPathWithPermission(tt.path, permissions)
				if found != tt.wantFound || !reflect.DeepEqual(got, tt.want) {
					t.Fatalf("iteration %d: MatchPathWithPermission(%q) = %v, %v; want %v, %v",
						i, tt.path, got, found, tt.want, tt.wantFound)
				}
			}
		})
	}
}

func TestMatchPathWithPermissionEquallySpecificIsDeterministic(t *testing.T) {
	permissions := map[string][]int{
		"/v1/item/:slug": {2},
		"/v1/item/:id":   {1},
	}

	for i := 0; i < iterations; i++ {
		got, found := MatchPathWithPermission("/v1/item/abc", permissions)
		if !found || !reflect.DeepEqual(got, []int{1}) {
			t.Fatalf("iteration %d: got %v, %v; want [1], true", i, got, found)
		}
	}
}
