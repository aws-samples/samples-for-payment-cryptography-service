package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

type KeyComponents struct {
	Original     []byte
	ComponentOne []byte
	ComponentTwo []byte
	KCV          string
}

func GenerateKeyComponents(keyHex string, kcv string) (*KeyComponents, error) {
	keyHex = strings.ReplaceAll(keyHex, " ", "")
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key hex: %w", err)
	}

	componentTwo := make([]byte, len(key))
	if _, err := rand.Read(componentTwo); err != nil {
		return nil, fmt.Errorf("failed to generate random component: %w", err)
	}

	componentOne := make([]byte, len(key))
	for i := 0; i < len(key); i++ {
		componentOne[i] = key[i] ^ componentTwo[i]
	}

	return &KeyComponents{
		Original:     key,
		ComponentOne: componentOne,
		ComponentTwo: componentTwo,
		KCV:          kcv,
	}, nil
}

func (kc *KeyComponents) String() string {
	return fmt.Sprintf(
		"Clear Key: %s\nKCV: %s\nComponents:\n  Component One: %s\n  Component Two: %s",
		strings.ToUpper(hex.EncodeToString(kc.Original)),
		kc.KCV,
		strings.ToUpper(hex.EncodeToString(kc.ComponentOne)),
		strings.ToUpper(hex.EncodeToString(kc.ComponentTwo)),
	)
}
