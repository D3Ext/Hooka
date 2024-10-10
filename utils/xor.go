package utils

func Xor(input, key []byte) (cipher []byte) {
  for i := 0; i < len(input); i++ {
    cipher = append(cipher, (input[i] ^ key[i % len(key)]))
  }

  return cipher
}

