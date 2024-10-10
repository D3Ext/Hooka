package utils

import (
  "crypto/md5"
  "crypto/sha1"
  "crypto/sha256"
  "encoding/hex"
)

func Md5(src string) string {
	hash := md5.Sum([]byte(src))
	return hex.EncodeToString(hash[:])
}

func Sha1(src string) string {
	hash := sha1.Sum([]byte(src))
	return hex.EncodeToString(hash[:])
}

func Sha256(src string) string {
	hash := sha256.Sum256([]byte(src))
	return hex.EncodeToString(hash[:])
}

