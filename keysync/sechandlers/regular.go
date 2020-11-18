package sechandlers

var (
	// RegularKeyHandler handles keys with type secret=key
	// In this case, each entry represents a file and the private key data
	// so no action is required.
	RegularKeyHandler SecretKeyHandler = func(data map[string][]byte) (map[string][]byte, error) {
		return data, nil
	}
)
