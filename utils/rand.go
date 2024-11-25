package utils

import (
  "math/rand/v2"
)

// Generate a random integer between range
func RandomInt(min, max int) int {
	return rand.IntN(max+1-min) + min
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Return random string on n length
func RandomString(n int) string {
  b := make([]byte, n)
  for i := range b {
    b[i] = letterBytes[rand.IntN(len(letterBytes))]
  }

  return string(b)
}

