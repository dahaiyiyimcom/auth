package pkg

import "strings"

// MatchPathWithPermission matches the requested path with defined permissions
func MatchPathWithPermission(requestedPath string, dynamicPermissions map[string]int) (int, bool) {
	for pattern, permission := range dynamicPermissions {
		if matchRoute(pattern, requestedPath) {
			return permission, true
		}
	}
	return 0, false
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
