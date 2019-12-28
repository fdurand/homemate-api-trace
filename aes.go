package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func AESEncrypt(src string, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if src == "" {
		fmt.Println("plain content empty")
	}
	ecb := cipher.NewCBCEncrypter(block, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return crypted
}

func AESDecrypt(crypt []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if len(crypt) == 0 {
		fmt.Println("plain content empty")
	}
	size := 16
	length := len(crypt)
	if len(crypt)%16 == 0 {
		length = len(crypt)
	} else {
		for i := 0; i < 16; i++ {
			length = len(crypt) + i
			if length%16 == 0 {
				break
			}
		}
	}
	decrypted := make([]byte, length)
	for bs, be := 0, size; bs < length; bs, be = bs+size, be+size {
		block.Decrypt(decrypted[bs:be], crypt[bs:be])
	}
	return PKCS5Trimming(decrypted)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
