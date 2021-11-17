package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

func AesEncryptCBC(origin []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	size := block.BlockSize()
	origin = pkcs5padding(origin, size)
	mode := cipher.NewCBCEncrypter(block, key[:size])
	encrypted := make([]byte, len(origin))
	mode.CryptBlocks(encrypted, origin)
	return encrypted, nil
}

func AesDecryptCBC(encrypt []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	size := block.BlockSize()
	mode := cipher.NewCBCDecrypter(block, key[:size])

	decrypt := make([]byte, len(encrypt))
	mode.CryptBlocks(decrypt, encrypt)
	decrypt = unpkcs5padding(decrypt)
	return decrypt, nil
}

func pkcs5padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	text := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, text...)
}

func unpkcs5padding(decrypt []byte) []byte {
	n := len(decrypt)
	unpadding := int(decrypt[n-1])
	return decrypt[:(n - unpadding)]
}
