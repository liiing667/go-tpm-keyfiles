package keyfile

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func policyFileFixture(t *testing.T, path string) []*TPMPolicy {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed reading policy file: %v", err)
	}
	var policies []*TPMPolicy
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		raw, err := hex.DecodeString(strings.TrimSpace(line))
		if err != nil {
			t.Fatalf("failed decoding policy line: %v", err)
		}
		policies = append(policies, &TPMPolicy{
			CommandCode:   int(binary.BigEndian.Uint32(raw[:4])),
			CommandPolicy: raw[4:],
		})
	}
	return policies
}

func TestLoadableKeyWithAuthPolicy(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	policies := policyFileFixture(t, "./testdata/policy.txt")

	key, err := NewLoadableKey(tpm, tpm2.TPMAlgECC, 256, []byte{},
		WithDescription("policy key"),
		WithAuthPolicy([]*TPMAuthPolicy{
			{Name: "pcr", Policy: policies},
			{Name: "authvalue", Policy: policies[1:]},
		}),
	)
	if err != nil {
		t.Fatalf("failed creating loadable key: %v", err)
	}

	// Round-trip the key through the on-disk encoding.
	decoded, err := Decode(key.Bytes())
	if err != nil {
		t.Fatalf("failed decoding key: %v", err)
	}

	selected, err := decoded.SelectAuthPolicy("pcr")
	if err != nil {
		t.Fatalf("failed selecting auth policy: %v", err)
	}
	wantDigest, err := key.AuthPolicy[0].Digest()
	if err != nil {
		t.Fatalf("failed computing digest: %v", err)
	}
	gotDigest, err := selected.Digest()
	if err != nil {
		t.Fatalf("failed computing digest: %v", err)
	}
	if !bytes.Equal(wantDigest, gotDigest) {
		t.Fatalf("selected policy identity changed across round-trip")
	}

	if _, err := decoded.SelectAuthPolicy(""); !errors.Is(err, ErrAmbiguousAuthPolicy) {
		t.Fatalf("expected ambiguous selection, got %v", err)
	}

	signer, err := decoded.Signer(tpm, []byte(""), []byte(""))
	if err != nil {
		t.Fatalf("couldn't create signer: %v", err)
	}

	h := crypto.SHA256.New()
	h.Write([]byte("heyho"))
	b := h.Sum(nil)

	sig, err := signer.Sign((io.Reader)(nil), b[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("failed signing: %v", err)
	}

	ok, err := decoded.Verify(crypto.SHA256, b[:], sig)
	if !ok || err != nil {
		t.Fatalf("invalid signature")
	}
}

func TestNewLoadableKey(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("message")
	}
	defer tpm.Close()
	_, err = NewLoadableKey(tpm, tpm2.TPMAlgECC, 256, []byte{},
		WithDescription("testkey"),
	)
	if err != nil {
		t.Fatalf("message")
	}
}

func TestSigning(t *testing.T) {
	cases := []struct {
		msg        string
		keytype    tpm2.TPMAlgID
		bits       int
		digest     crypto.Hash
		filekey    []byte
		pin        []byte
		signpin    []byte
		shouldfail bool
	}{
		{
			msg:     "ecdsa - test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:     "ecdsa - test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:        "ecdsa - test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
			keytype:    tpm2.TPMAlgECC,
			digest:     crypto.SHA256,
			bits:       256,
		},
		{
			msg:     "ecdsa - test encryption/decrypt - no pin for key, pin for sign",
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgECC,
			digest:  crypto.SHA256,
			bits:    256,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin - sha512",
			filekey: []byte("this is a test filekey"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA512,
			bits:    2048,
		},
		// TODO: We should probably support this
		// {
		// 	msg:     "ecdsa - test encryption/decrypt - no pin - sha512",
		// 	filekey: []byte("this is a test filekey"),
		// 	keytype: tpm2.TPMAlgECDSA,
		// 	digest:  crypto.SHA512,
		// 	bits:    256,
		// },
		{
			msg:     "rsa - test encryption/decrypt - pin",
			filekey: []byte("this is a test filekey"),
			pin:     []byte("123"),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
		{
			msg:        "rsa - test encryption/decrypt - no pin for sign",
			filekey:    []byte("this is a test filekey"),
			pin:        []byte("123"),
			shouldfail: true,
			keytype:    tpm2.TPMAlgRSA,
			digest:     crypto.SHA256,
			bits:       2048,
		},
		{
			msg:     "rsa - test encryption/decrypt - no pin for key, pin for sign",
			filekey: []byte("this is a test filekey"),
			pin:     []byte(""),
			signpin: []byte("123"),
			keytype: tpm2.TPMAlgRSA,
			digest:  crypto.SHA256,
			bits:    2048,
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			// Always re-init simulator as the Signer is going to close it,
			// and we can't retain state.
			tpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatal(err)
			}
			defer tpm.Close()

			h := c.digest.New()
			h.Write([]byte("heyho"))
			b := h.Sum(nil)

			k, err := NewLoadableKey(tpm, c.keytype, c.bits, []byte(""),
				WithUserAuth(c.pin),
			)
			if err != nil {
				t.Fatalf("couldn't create new loadable key: %v", err)
			}

			signer, err := k.Signer(tpm, []byte(""), c.signpin)
			if err != nil {
				t.Fatalf("couldn't create signer: %v", err)
			}

			sig, err := signer.Sign((io.Reader)(nil), b[:], c.digest)
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("%v", err)
			}

			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("failed test: %v", err)
			}

			if c.shouldfail {
				t.Fatalf("test should be failing")
			}

			ok, err := k.Verify(c.digest, b[:], sig)
			if !ok || err != nil {
				t.Fatalf("invalid signature")
			}
		})
	}
}

func TestSigningWithOwnerPassword(t *testing.T) {
	ownerPassword := []byte("testPassword")

	cases := []struct {
		msg           string
		keytype       tpm2.TPMAlgID
		bits          int
		digest        crypto.Hash
		filekey       []byte
		pin           []byte
		signpin       []byte
		ownerpassword []byte
		shouldfail    bool
	}{
		{
			msg:           "ecdsa - test encryption/decrypt - no pin",
			filekey:       []byte("this is a test filekey"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			ownerpassword: ownerPassword,
		},
		{
			msg:           "ecdsa - test encryption/decrypt - pin",
			filekey:       []byte("this is a test filekey"),
			pin:           []byte("123"),
			signpin:       []byte("123"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			ownerpassword: ownerPassword,
		},
		{
			msg:           "ecdsa - test encryption/decrypt - no pin - invalid owner password",
			filekey:       []byte("this is a test filekey"),
			keytype:       tpm2.TPMAlgECC,
			digest:        crypto.SHA256,
			bits:          256,
			shouldfail:    true,
			ownerpassword: []byte("invalidPassword"),
		},
	}

	for n, c := range cases {
		t.Run(fmt.Sprintf("case %d, %s", n, c.msg), func(t *testing.T) {
			// Always re-init simulator as the Signer is going to close it,
			// and we can't retain state.
			tpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatal(err)
			}
			defer tpm.Close()

			hca := tpm2.HierarchyChangeAuth{
				AuthHandle: tpm2.TPMRHOwner,
				NewAuth: tpm2.TPM2BAuth{
					Buffer: ownerPassword,
				},
			}
			_, err = hca.Execute(tpm)
			if err != nil {
				t.Errorf("failed HierarchyChangeAuth: %v", err)
			}

			h := c.digest.New()
			h.Write([]byte("heyho"))
			b := h.Sum(nil)

			k, err := NewLoadableKey(tpm, c.keytype, c.bits, c.ownerpassword,
				WithUserAuth(c.pin),
			)
			if err != nil {
				if c.shouldfail {
					return
				}
				t.Fatalf("%v", err)
			}

			signer, err := k.Signer(tpm, c.ownerpassword, c.signpin)
			if err != nil {
				t.Fatalf("couldn't create signer: %v", err)
			}

			sig, err := signer.Sign((io.Reader)(nil), b[:], c.digest)
			if err != nil {
				if c.shouldfail {
					t.Fatalf("test should be failing")
				}
				t.Fatalf("%v", err)
			}

			ok, err := k.Verify(c.digest, b[:], sig)
			if !ok || err != nil {
				t.Fatalf("invalid signature")
			}
		})
	}
}
