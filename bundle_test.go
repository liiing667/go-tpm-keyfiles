package keyfile_test

import (
	"bytes"
	"encoding/pem"
	"errors"
	"testing"

	. "github.com/foxboron/go-tpm-keyfiles"
)

var (
	testKeyRSA  = "./testdata/rsa-key.tpm"
	testKeyP256 = "./testdata/p256-authvalue.tpm"
)

func testCertBlock() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not a real certificate"),
	})
}

func TestDecodeBundle(t *testing.T) {
	rsaKey := mustOpen(testKeyRSA)
	p256Key := mustOpen(testKeyP256)
	cert := testCertBlock()

	for _, tt := range []struct {
		name         string
		bundle       []byte
		wantKeys     int
		wantUnknown  int
		wantTrailing bool
		wantDecode   error
	}{
		{
			name:     "single key",
			bundle:   rsaKey,
			wantKeys: 1,
		},
		{
			name:       "duplicate keys",
			bundle:     bytes.Join([][]byte{rsaKey, p256Key}, nil),
			wantKeys:   2,
			wantDecode: ErrDuplicateKeys,
		},
		{
			name:        "key with trailing certificate",
			bundle:      bytes.Join([][]byte{rsaKey, cert}, nil),
			wantKeys:    1,
			wantUnknown: 1,
			wantDecode:  ErrUnknownBlocks,
		},
		{
			name:        "certificate before key",
			bundle:      bytes.Join([][]byte{cert, rsaKey}, nil),
			wantKeys:    1,
			wantUnknown: 1,
			wantDecode:  ErrUnknownBlocks,
		},
		{
			name:         "key with trailing garbage",
			bundle:       append(rsaKey, []byte("garbage\n")...),
			wantKeys:     1,
			wantTrailing: true,
			wantDecode:   ErrTrailingData,
		},
		{
			name:         "key with malformed pem tail",
			bundle:       append(rsaKey, []byte("-----BEGIN TSS2 PRIVATE KEY-----\n")...),
			wantKeys:     1,
			wantTrailing: true,
			wantDecode:   ErrTrailingData,
		},
		{
			name:        "certificate only",
			bundle:      cert,
			wantUnknown: 1,
			wantDecode:  ErrNotTPMKey,
		},
		{
			name:         "garbage only",
			bundle:       []byte("garbage\n"),
			wantTrailing: true,
			wantDecode:   errors.New("not an armored key"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bundle, err := DecodeBundle(tt.bundle)
			if err != nil {
				t.Fatalf("failed decoding bundle: %v", err)
			}

			if len(bundle.Keys) != tt.wantKeys {
				t.Fatalf("expected %d keys, got %d", tt.wantKeys, len(bundle.Keys))
			}
			if len(bundle.Unknown) != tt.wantUnknown {
				t.Fatalf("expected %d unknown blocks, got %d", tt.wantUnknown, len(bundle.Unknown))
			}
			if tt.wantTrailing != (len(bundle.Trailing) != 0) {
				t.Fatalf("expected trailing data: %v, got %q", tt.wantTrailing, bundle.Trailing)
			}

			_, err = Decode(tt.bundle)
			if tt.wantDecode == nil && err != nil {
				t.Fatalf("expected decode to succeed, got: %v", err)
			}
			if tt.wantDecode != nil {
				if err == nil {
					t.Fatalf("expected decode to fail with %v", tt.wantDecode)
				}
				if !errors.Is(err, tt.wantDecode) && err.Error() != tt.wantDecode.Error() {
					t.Fatalf("expected error %v, got %v", tt.wantDecode, err)
				}
			}
		})
	}
}

func TestDecodeBundleRoundtrip(t *testing.T) {
	key, err := Decode(mustOpen(testKeyRSA))
	if err != nil {
		t.Fatalf("failed decoding key: %v", err)
	}

	bundle, err := DecodeBundle(key.Bytes())
	if err != nil {
		t.Fatalf("failed decoding bundle: %v", err)
	}
	if len(bundle.Keys) != 1 || len(bundle.Unknown) != 0 || len(bundle.Trailing) != 0 {
		t.Fatalf("expected single key bundle, got %d keys, %d unknown, %q trailing",
			len(bundle.Keys), len(bundle.Unknown), bundle.Trailing)
	}

	if !bytes.Equal(bundle.Keys[0].Bytes(), key.Bytes()) {
		t.Fatalf("roundtripped key is not equal")
	}
}
