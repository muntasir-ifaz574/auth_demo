package password

import "golang.org/x/crypto/bcrypt"

// Hash converts a plain text password into a bcrypt hash.
func Hash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

// Compare checks if a plaintext password matches the stored bcrypt hash.
func Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
