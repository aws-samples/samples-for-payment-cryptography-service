package utils

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func ParseHexString(hexStr string) ([]byte, error) {
	cleaned := strings.ReplaceAll(hexStr, " ", "")

	if len(cleaned) == 0 {
		return nil, fmt.Errorf("empty hex string")
	}

	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("hex string must have even length")
	}

	data, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}

	return data, nil
}
