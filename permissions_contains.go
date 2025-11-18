package auth

func PermissionsContains(s []int, p []int) bool {

	for _, v := range s {
		for _, i := range p {
			if v == Admin || v == i {
				return true
			}
			if i == AllUser {
				return true
			}
		}
	}

	return false
}
