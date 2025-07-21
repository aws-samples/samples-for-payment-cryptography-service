package enums

import "slices"

type KeyAlgorithm string

var (
	KeyAlgorithmTDES2Key KeyAlgorithm = "TDES2Key"
	KeyAlgorithmTDES3Key KeyAlgorithm = "TDES3Key"
	KeyAlgorithmAES128   KeyAlgorithm = "AES128"
	KeyAlgorithmAES192   KeyAlgorithm = "AES192"
	KeyAlgorithmAES256   KeyAlgorithm = "AES256"
)

func (KeyAlgorithm) Values() []KeyAlgorithm {
	return []KeyAlgorithm{
		KeyAlgorithmTDES2Key,
		KeyAlgorithmTDES3Key,
		KeyAlgorithmAES128,
		KeyAlgorithmAES192,
		KeyAlgorithmAES256,
	}
}

func (k KeyAlgorithm) Valid() bool {
	return slices.Contains(k.Values(), k)
}
