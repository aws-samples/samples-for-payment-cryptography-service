package utils

import (
	"crypto/aes"
	"crypto/des"
	"encoding/hex"
	"fmt"
	
	"github.com/aead/cmac"
)

func CalculateKCV(key []byte, algorithm string) (string, error) {
	zeroBlock := make([]byte, 8)
	
	if algorithm == "A" {
		zeroBlock = make([]byte, 16)
		
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("failed to create AES cipher: %w", err)
		}
		
		mac, err := cmac.New(block)
		if err != nil {
			return "", fmt.Errorf("failed to create CMAC: %w", err)
		}
		
		mac.Write(zeroBlock)
		
		macResult := mac.Sum(nil)
		return hex.EncodeToString(macResult[:3]), nil
	} else {
		var keyToUse []byte
		if len(key) == 16 {
			keyToUse = make([]byte, 24)
			copy(keyToUse[0:16], key)
			copy(keyToUse[16:24], key[0:8])
		} else {
			keyToUse = key
		}
		
		block, err := des.NewTripleDESCipher(keyToUse)
		if err != nil {
			return "", fmt.Errorf("failed to create 3DES cipher: %w", err)
		}
		
		encrypted := make([]byte, 8)
		block.Encrypt(encrypted, zeroBlock)
		
		return hex.EncodeToString(encrypted[:3]), nil
	}
}