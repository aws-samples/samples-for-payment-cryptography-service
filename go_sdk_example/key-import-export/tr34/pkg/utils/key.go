package utils

import (
	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
)

func DetermineKeyAlgorithm(key []byte, algorithm string) types.KeyAlgorithm {
	if algorithm == "A" {
		switch len(key) {
		case 16:
			return types.KeyAlgorithmAes128
		case 24:
			return types.KeyAlgorithmAes192
		case 32:
			return types.KeyAlgorithmAes256
		}
	} else if algorithm == "T" {
		switch len(key) {
		case 16:
			return types.KeyAlgorithmTdes2key
		case 24:
			return types.KeyAlgorithmTdes3key
		}
	}
	return ""
}

func DetermineKeyTypeString(attrs *types.KeyAttributes) string {
	if attrs == nil {
		return "UNKNOWN"
	}

	switch attrs.KeyAlgorithm {
	case types.KeyAlgorithmTdes2key:
		return "TDES_2KEY"
	case types.KeyAlgorithmTdes3key:
		return "TDES_3KEY"
	case types.KeyAlgorithmAes128:
		return "AES_128"
	case types.KeyAlgorithmAes192:
		return "AES_192"
	case types.KeyAlgorithmAes256:
		return "AES_256"
	default:
		return string(attrs.KeyAlgorithm)
	}
}

func GetKeyCheckValueAlgorithm(algorithm string) types.KeyCheckValueAlgorithm {
	if algorithm == "A" {
		return types.KeyCheckValueAlgorithmCmac
	}
	return types.KeyCheckValueAlgorithmAnsiX924
}