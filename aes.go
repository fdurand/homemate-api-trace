package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

func AESEncrypt(content []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	size := 16
	length := len(content)
	if len(content)%16 == 0 {
		length = len(content)
	} else {
		for i := 0; i < 16; i++ {
			length = len(content) + i
			if length%16 == 0 {
				break
			}
		}
	}

	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	for bs, be := 0, size; bs < length; bs, be = bs+size, be+size {
		block.Encrypt(crypted[bs:be], content[bs:be])
	}

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
