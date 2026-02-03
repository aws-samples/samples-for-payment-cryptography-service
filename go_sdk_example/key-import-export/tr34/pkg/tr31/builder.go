package tr31

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func BuildTR31Block(clearKey []byte, options ImportOptions) (string, error) {
	if options.KEK != nil && len(options.KEK) > 0 {
		wrapper := NewWrapper(options.KEK)
		return wrapper.Wrap(clearKey, options)
	}

	return buildSimplifiedTR31Block(clearKey, options)
}

func buildSimplifiedTR31Block(clearKey []byte, options ImportOptions) (string, error) {
	header := buildTR31Header(options)

	blockSize := 8
	if options.Algorithm == "A" {
		blockSize = 16
	}

	keyData := clearKey
	if len(keyData)%blockSize != 0 {
		padding := blockSize - (len(keyData) % blockSize)
		for i := 0; i < padding; i++ {
			keyData = append(keyData, byte(padding))
		}
	}

	encKeyHex := hex.EncodeToString(keyData)

	macSize := 8
	if options.Algorithm == "A" {
		macSize = 16
	}
	mac := make([]byte, macSize)
	for i := range mac {
		mac[i] = 0xFF
	}
	macHex := hex.EncodeToString(mac)

	payload := encKeyHex + macHex
	totalLen := 16 + len(payload)

	header = header[:1] + fmt.Sprintf("%04d", totalLen) + header[5:]

	tr31Block := header + strings.ToUpper(payload)

	return tr31Block, nil
}

func buildTR31Header(options ImportOptions) string {
	versionID := "B"
	if options.Algorithm == "A" {
		versionID = "D"
	}
	if options.VersionID != "" {
		versionID = options.VersionID
	}

	header := versionID
	header += "9999"
	header += options.KeyType
	header += options.Algorithm
	header += options.ModeOfUse
	header += "00"
	header += options.ExportMode
	header += "00"
	header += "00"

	return header
}
