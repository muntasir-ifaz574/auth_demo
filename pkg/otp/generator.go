package otp

import (
	"crypto/rand"
	"math/big"
)

// GenerateNumeric returns a zero-padded n digit code using crypto randomness.
func GenerateNumeric(n int) (string, error) {
	if n <= 0 {
		n = 6
	}
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		buf[i] = byte('0' + num.Int64())
	}
	return string(buf), nil
}
