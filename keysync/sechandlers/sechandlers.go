package sechandlers

// SecretKeyHandler is a function type that maps secret data into the
// filename/private key data to be stored. This is useful for handling
// secrets that may require an additional step of unwrapping, formatting, etc.
type SecretKeyHandler func(map[string][]byte) (map[string][]byte, error)
