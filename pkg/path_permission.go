package pkg

import "strings"

// MatchPathWithPermission matches the requested path with defined permissions.
// When several patterns match, the most specific one wins (see moreSpecific),
// so e.g. /product/list takes precedence over /product/:id regardless of map
// iteration order.
func MatchPathWithPermission(requestedPath string, dynamicPermissions map[string][]int) ([]int, bool) {
	var (
		bestPattern    string
		bestPermission []int
		found          bool
	)

	for pattern, permission := range dynamicPermissions {
		if !matchRoute(pattern, requestedPath) {
			continue
		}
		if !found || moreSpecific(pattern, bestPattern) {
			bestPattern, bestPermission, found = pattern, permission, true
		}
	}

	return bestPermission, found
}

// moreSpecific reports whether pattern a takes precedence over pattern b when
// both match the same path. Segments are compared left to right and, at the
// first position where one is static and the other a parameter, the static one
// wins. Equally specific patterns are ordered lexically so the result never
// depends on map iteration order.
func moreSpecific(a, b string) bool {
	aParts := strings.Split(strings.Trim(a, "/"), "/")
	bParts := strings.Split(strings.Trim(b, "/"), "/")

	for i := 0; i < len(aParts) && i < len(bParts); i++ {
		aParam := strings.HasPrefix(aParts[i], ":")
		bParam := strings.HasPrefix(bParts[i], ":")
		if aParam != bParam {
			return !aParam
		}
	}

	return a < b
}

// matchRoute compares a route pattern with an actual path
//   - routeDef: e.g. /api/test/:id
//   - path: e.g. /api/test/453
func matchRoute(routeDef, path string) bool {
	defParts := strings.Split(strings.Trim(routeDef, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")

	// Return false early if segment lengths don't match
	if len(defParts) != len(pathParts) {
		return false
	}

	for i, seg := range defParts {
		// If segment is a parameter (e.g., :id, :xyz)
		if strings.HasPrefix(seg, ":") {
			// // Ensure parameter segment is numeric
			// if !isNumeric(pathParts[i]) {
			// 	return false
			// }
			continue
		}
		// If not a parameter, check for exact match
		if seg != pathParts[i] {
			return false
		}
	}

	return true
}

// isNumeric checks if a string contains only numeric characters
func isNumeric(str string) bool {
	for _, c := range str {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
