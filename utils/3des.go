package utils

import (
	"crypto/cipher"
	"crypto/des"
)

func TripleDesEncrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := key
	iv := ciphertext[:des.BlockSize]

	origData := PKCS5Padding(data, block.BlockSize())

	mode := cipher.NewCBCEncrypter(block, iv)

	encrypted := make([]byte, len(origData))

	mode.CryptBlocks(encrypted, origData)

	return encrypted, nil
}

func TripleDesDecrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := key
	iv := ciphertext[:des.BlockSize]

	decrypter := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(data))
	decrypter.CryptBlocks(decrypted, data)
	decrypted = PKCS5Trimming(decrypted)

	return decrypted, nil
}
