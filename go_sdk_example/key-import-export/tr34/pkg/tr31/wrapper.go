package tr31

import (
	"fmt"
	"strings"

	moovtr31 "github.com/moov-io/tr31/pkg/tr31"
)

type Wrapper struct {
	kbpk []byte
}

func NewWrapper(kek []byte) *Wrapper {
	return &Wrapper{
		kbpk: kek,
	}
}

func (w *Wrapper) Wrap(clearKey []byte, options ImportOptions) (string, error) {
	versionID := w.determineVersionID(options)

	header, err := moovtr31.NewHeader(
		versionID,
		options.KeyType,
		options.Algorithm,
		options.ModeOfUse,
		"00", // Version number
		options.ExportMode,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create TR-31 header: %w", err)
	}

	keyBlock, err := moovtr31.NewKeyBlock(w.kbpk, header)
	if err != nil {
		return "", fmt.Errorf("failed to create key block: %w", err)
	}

	wrappedBlock, err := keyBlock.Wrap(clearKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to wrap key: %w", err)
	}

	return strings.ToUpper(wrappedBlock), nil
}

func (w *Wrapper) Unwrap(keyBlock string) ([]byte, error) {
	kb, err := moovtr31.NewKeyBlock(w.kbpk, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create key block: %w", err)
	}

	clearKey, err := kb.Unwrap(keyBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	return clearKey, nil
}

func (w *Wrapper) GetHeader(keyBlock string) (*moovtr31.Header, error) {
	header := moovtr31.DefaultHeader()
	_, err := header.Load(keyBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to load header: %w", err)
	}
	return header, nil
}

func (w *Wrapper) determineVersionID(options ImportOptions) string {
	if options.VersionID != "" {
		return options.VersionID
	}

	if options.Algorithm == "A" {
		return moovtr31.TR31_VERSION_D // AES uses version D
	}

	return moovtr31.TR31_VERSION_B // TDES uses version B by default
}
