package utils

import (
	"math/rand"
	"time"
)

// Generate a random integer between range
func RandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	rand_int := rand.Intn(max-min+1) + min
	return rand_int
}

// Return random string based on an integer (length)
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}

	// Ensure the first character is not an integer
	for b[0] >= '0' && b[0] <= '9' {
		b[0] = charset[seededRand.Intn(len(charset))]
	}

	return string(b)
}

