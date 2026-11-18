package keyfile

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
)

// Errors describing why a bundle is not accepted as a single key.
var (
	ErrDuplicateKeys = errors.New("multiple TSS2 keys in bundle")
	ErrUnknownBlocks = errors.New("unknown PEM blocks in bundle")
	ErrTrailingData  = errors.New("trailing data after PEM blocks")
)

var pemStart = []byte("-----BEGIN ")

// Bundle is the complete inventory of a PEM bundle. Every block in the
// input is accounted for: parsed TSS2 keys, unknown PEM blocks and any
// trailing non-PEM bytes.
type Bundle struct {
	// Keys are the parsed TSS2 PRIVATE KEY blocks, in order of appearance.
	Keys []*TPMKey
	// Unknown are PEM blocks of any other type, in order of appearance.
	Unknown []*pem.Block
	// Trailing are the non-PEM bytes following the last block, if any.
	Trailing []byte
}

// DecodeBundle parses all PEM blocks in b and returns the complete
// inventory of the bundle. It only fails if a TSS2 PRIVATE KEY block
// can not be parsed.
func DecodeBundle(b []byte) (*Bundle, error) {
	var bundle Bundle
	rest := b
	for {
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, pemStart) {
			bundle.Trailing = rest
			break
		}
		block, r := pem.Decode(rest)
		if block == nil {
			// Malformed PEM block, treat the remainder as trailing data.
			bundle.Trailing = rest
			break
		}
		rest = r
		if block.Type != pemType {
			bundle.Unknown = append(bundle.Unknown, block)
			continue
		}
		key, err := Parse(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %q block: %w", pemType, err)
		}
		bundle.Keys = append(bundle.Keys, key)
	}
	return &bundle, nil
}

// Single accepts the bundle only if it contains exactly one TSS2 key and
// nothing else. Duplicate keys, unknown blocks and trailing data are all
// rejected with explicit errors.
func (b *Bundle) Single() (*TPMKey, error) {
	if len(b.Keys) == 0 {
		if len(b.Unknown) != 0 {
			return nil, ErrNotTPMKey
		}
		return nil, fmt.Errorf("not an armored key")
	}
	if len(b.Keys) > 1 {
		return nil, fmt.Errorf("%w: got %d keys", ErrDuplicateKeys, len(b.Keys))
	}
	if len(b.Unknown) != 0 {
		return nil, fmt.Errorf("%w: got %q", ErrUnknownBlocks, b.Unknown[0].Type)
	}
	if len(b.Trailing) != 0 {
		return nil, ErrTrailingData
	}
	return b.Keys[0], nil
}
