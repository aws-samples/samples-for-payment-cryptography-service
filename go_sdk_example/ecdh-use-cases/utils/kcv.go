package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// CalculateTDESKCV calculates a TDES KCV (Key Check Value).
//
// It panics if unable to create a TDES cipher block e.g. when
// key is not 24 bytes long.
func CalculateTDESKCV(key []byte) string {
	blk, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}

	encryptedMsg := make([]byte, des.BlockSize)
	blk.Encrypt(encryptedMsg, bytes.Repeat([]byte{0x00}, des.BlockSize))
	return strings.ToUpper(hex.EncodeToString(encryptedMsg[:3]))
}

// CalculateAESKCV calculates an AES KCV (Key Check Value).
//
// It panics if unable to create an AES cipher block e.g. when
// key is not of an acceptable length (16/128, 24/192 or 32/256 bytes/bits).
func CalculateAESKCV(key []byte) string {
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	zeroBlock := bytes.Repeat([]byte{0x00}, aes.BlockSize)

	subKey1 := make([]byte, aes.BlockSize)
	blk.Encrypt(subKey1, zeroBlock)
	xorNeeded := subKey1[0]>>7 == 1
	for i, overflow := len(subKey1)-1, byte(0); i >= 0; i-- {
		var tmp = subKey1[i]
		subKey1[i] = (tmp << 1) | overflow
		overflow = tmp >> 7
	}
	if xorNeeded {
		rb := append(bytes.Repeat([]byte{0x00}, aes.BlockSize-1), 0x87)
		subtle.XORBytes(subKey1, subKey1, rb)
	}

	data := make([]byte, len(subKey1))
	subtle.XORBytes(data, subKey1, zeroBlock)

	encryptedMsg := make([]byte, aes.BlockSize)
	blk.Encrypt(encryptedMsg, data)
	return strings.ToUpper(hex.EncodeToString(encryptedMsg[:3]))
}
