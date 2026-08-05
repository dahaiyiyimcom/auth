package auth

const Admin = 1
const AllUser = 999

func PermissionsContains(roles []int, permissions []int) bool {
	for _, permission := range permissions {
		if permission == AllUser {
			return true
		}
	}

	for _, role := range roles {
		for _, permission := range permissions {
			if role == Admin || role == permission {
				return true
			}
		}
	}

	return false
}
