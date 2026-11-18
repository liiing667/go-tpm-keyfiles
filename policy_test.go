package keyfile_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	. "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
)

// mustReadPolicyFile reads the testdata/policy.txt fixture. Every line is
// the hex encoding of a big-endian uint32 command code followed by the
// command policy bytes.
func mustReadPolicyFile(t *testing.T, path string) []*TPMPolicy {
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
		if len(raw) < 4 {
			t.Fatalf("policy line too short: %q", line)
		}
		policies = append(policies, &TPMPolicy{
			CommandCode:   int(binary.BigEndian.Uint32(raw[:4])),
			CommandPolicy: raw[4:],
		})
	}
	return policies
}

func mustFixturePolicies(t *testing.T) []*TPMPolicy {
	t.Helper()
	policies := mustReadPolicyFile(t, "./testdata/policy.txt")
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies in fixture, got %d", len(policies))
	}
	// TPM_CC_PolicyPCR with arguments, TPM_CC_PolicyAuthValue without.
	if policies[0].CommandCode != 0x17f {
		t.Fatalf("expected first command code 0x17f, got 0x%x", policies[0].CommandCode)
	}
	if policies[1].CommandCode != 0x16b {
		t.Fatalf("expected second command code 0x16b, got 0x%x", policies[1].CommandCode)
	}
	return policies
}

func TestTPMPolicyEqual(t *testing.T) {
	policies := mustFixturePolicies(t)
	if !policies[0].Equal(policies[0]) {
		t.Fatalf("policy should equal itself")
	}
	if policies[0].Equal(policies[1]) {
		t.Fatalf("distinct policies should not be equal")
	}
	clone := &TPMPolicy{CommandCode: policies[0].CommandCode, CommandPolicy: policies[0].CommandPolicy}
	if !policies[0].Equal(clone) {
		t.Fatalf("identical policy items should be equal")
	}
}

func TestTPMAuthPolicyDigest(t *testing.T) {
	policies := mustFixturePolicies(t)
	auth := &TPMAuthPolicy{Name: "fixture", Policy: policies}

	digest, err := auth.Digest()
	if err != nil {
		t.Fatalf("failed computing digest: %v", err)
	}
	if len(digest) != 32 {
		t.Fatalf("expected 32 byte digest, got %d", len(digest))
	}

	// Deterministic across calls and independent of the set name.
	again, err := (&TPMAuthPolicy{Name: "other", Policy: policies}).Digest()
	if err != nil {
		t.Fatalf("failed computing digest: %v", err)
	}
	if !bytes.Equal(digest, again) {
		t.Fatalf("digest should be deterministic and name independent")
	}

	// Same command codes but different policy bytes is a different identity.
	altered := &TPMAuthPolicy{Policy: []*TPMPolicy{
		{CommandCode: policies[0].CommandCode, CommandPolicy: []byte("other digest")},
		policies[1],
	}}
	alteredDigest, err := altered.Digest()
	if err != nil {
		t.Fatalf("failed computing digest: %v", err)
	}
	if bytes.Equal(digest, alteredDigest) {
		t.Fatalf("same command codes with different digests must not share identity")
	}

	// Item order is part of the identity.
	reversed := &TPMAuthPolicy{Policy: []*TPMPolicy{policies[1], policies[0]}}
	reversedDigest, err := reversed.Digest()
	if err != nil {
		t.Fatalf("failed computing digest: %v", err)
	}
	if bytes.Equal(digest, reversedDigest) {
		t.Fatalf("reordered policy set must not share identity")
	}

	// Empty sets fail closed.
	for _, empty := range []*TPMAuthPolicy{
		nil,
		{},
		{Name: "empty", Policy: []*TPMPolicy{}},
		{Policy: []*TPMPolicy{nil}},
	} {
		if _, err := empty.Digest(); !errors.Is(err, ErrEmptyAuthPolicy) {
			t.Fatalf("expected ErrEmptyAuthPolicy, got %v", err)
		}
	}
}

func TestSelectAuthPolicy(t *testing.T) {
	policies := mustFixturePolicies(t)
	other := &TPMPolicy{CommandCode: policies[0].CommandCode, CommandPolicy: []byte("other digest")}

	named := func(name string, items ...*TPMPolicy) *TPMAuthPolicy {
		return &TPMAuthPolicy{Name: name, Policy: items}
	}

	for _, tt := range []struct {
		name       string
		key        *TPMKey
		selectName string
		want       *TPMAuthPolicy
		wantErr    error
	}{
		{
			name: "no policies yields nil",
			key:  &TPMKey{},
			want: nil,
		},
		{
			name: "legacy policy field is selectable",
			key:  &TPMKey{Policy: policies},
			want: &TPMAuthPolicy{Policy: policies},
		},
		{
			name:       "legacy policy field is not named",
			key:        &TPMKey{Policy: policies},
			selectName: "pcr",
			wantErr:    ErrNoAuthPolicy,
		},
		{
			name: "single unnamed policy",
			key:  &TPMKey{AuthPolicy: []*TPMAuthPolicy{named("", policies...)}},
			want: named("", policies...),
		},
		{
			name: "single named policy selected by empty name",
			key:  &TPMKey{AuthPolicy: []*TPMAuthPolicy{named("pcr", policies...)}},
			want: named("pcr", policies...),
		},
		{
			name:       "single named policy selected by name",
			key:        &TPMKey{AuthPolicy: []*TPMAuthPolicy{named("pcr", policies...)}},
			selectName: "pcr",
			want:       named("pcr", policies...),
		},
		{
			name: "multiple policies selected by name",
			key: &TPMKey{AuthPolicy: []*TPMAuthPolicy{
				named("pcr", policies...),
				named("authvalue", policies[1]),
			}},
			selectName: "authvalue",
			want:       named("authvalue", policies[1]),
		},
		{
			name: "multiple policies with empty name is ambiguous",
			key: &TPMKey{AuthPolicy: []*TPMAuthPolicy{
				named("pcr", policies...),
				named("authvalue", policies[1]),
			}},
			wantErr: ErrAmbiguousAuthPolicy,
		},
		{
			name: "identical duplicate names collapse",
			key: &TPMKey{AuthPolicy: []*TPMAuthPolicy{
				named("pcr", policies...),
				named("pcr", policies...),
			}},
			selectName: "pcr",
			want:       named("pcr", policies...),
		},
		{
			name: "duplicate names with distinct digests are ambiguous",
			key: &TPMKey{AuthPolicy: []*TPMAuthPolicy{
				named("pcr", policies...),
				named("pcr", other, policies[1]),
			}},
			selectName: "pcr",
			wantErr:    ErrAmbiguousAuthPolicy,
		},
		{
			name:       "unknown name fails",
			key:        &TPMKey{AuthPolicy: []*TPMAuthPolicy{named("pcr", policies...)}},
			selectName: "unknown",
			wantErr:    ErrNoAuthPolicy,
		},
		{
			name: "empty policy set fails closed",
			key: &TPMKey{AuthPolicy: []*TPMAuthPolicy{
				named("pcr", policies...),
				named("empty"),
			}},
			selectName: "pcr",
			wantErr:    ErrEmptyAuthPolicy,
		},
		{
			name:       "nil policy set fails closed",
			key:        &TPMKey{AuthPolicy: []*TPMAuthPolicy{nil}},
			selectName: "",
			wantErr:    ErrEmptyAuthPolicy,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.key.SelectAuthPolicy(tt.selectName)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, err)
			}
			if tt.wantErr != nil {
				return
			}
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected no policy, got %v", got)
				}
				return
			}
			if got == nil || !got.Equal(tt.want) {
				t.Fatalf("selected policy does not match expected policy")
			}
		})
	}
}

func TestAuthPolicyMarshalRoundTrip(t *testing.T) {
	policies := mustFixturePolicies(t)

	for _, tt := range []struct {
		name string
		key  *TPMKey
	}{
		{
			name: "single auth policy",
			key: &TPMKey{
				Keytype:   OIDLoadableKey,
				EmptyAuth: true,
				Parent:    tpm2.TPMHandle(0x40000001),
				Pubkey:    tpm2.New2B(tpm2.ECCSRKTemplate),
				Privkey:   tpm2.TPM2BPrivate{Buffer: []byte("some data")},
				AuthPolicy: []*TPMAuthPolicy{
					{Name: "pcr", Policy: policies},
				},
			},
		},
		{
			name: "multiple auth policies",
			key: &TPMKey{
				Keytype:   OIDLoadableKey,
				EmptyAuth: true,
				Parent:    tpm2.TPMHandle(0x40000001),
				Pubkey:    tpm2.New2B(tpm2.ECCSRKTemplate),
				Privkey:   tpm2.TPM2BPrivate{Buffer: []byte("some data")},
				AuthPolicy: []*TPMAuthPolicy{
					{Name: "pcr", Policy: policies},
					{Policy: []*TPMPolicy{policies[1]}},
				},
			},
		},
		{
			name: "legacy policy",
			key: &TPMKey{
				Keytype:   OIDLoadableKey,
				EmptyAuth: true,
				Parent:    tpm2.TPMHandle(0x40000001),
				Pubkey:    tpm2.New2B(tpm2.ECCSRKTemplate),
				Privkey:   tpm2.TPM2BPrivate{Buffer: []byte("some data")},
				Policy:    policies,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := Decode(tt.key.Bytes())
			if err != nil {
				t.Fatalf("failed decoding key: %v", err)
			}

			if len(decoded.AuthPolicy) != len(tt.key.AuthPolicy) {
				t.Fatalf("auth policy count mismatch: %d != %d", len(decoded.AuthPolicy), len(tt.key.AuthPolicy))
			}
			for i := range tt.key.AuthPolicy {
				if !decoded.AuthPolicy[i].Equal(tt.key.AuthPolicy[i]) {
					t.Fatalf("auth policy %d does not round-trip", i)
				}
				wantDigest, err := tt.key.AuthPolicy[i].Digest()
				if err != nil {
					t.Fatalf("failed computing digest: %v", err)
				}
				gotDigest, err := decoded.AuthPolicy[i].Digest()
				if err != nil {
					t.Fatalf("failed computing digest: %v", err)
				}
				if !bytes.Equal(wantDigest, gotDigest) {
					t.Fatalf("auth policy %d identity changed across round-trip", i)
				}
			}

			if len(decoded.Policy) != len(tt.key.Policy) {
				t.Fatalf("legacy policy count mismatch: %d != %d", len(decoded.Policy), len(tt.key.Policy))
			}
			for i := range tt.key.Policy {
				if !decoded.Policy[i].Equal(tt.key.Policy[i]) {
					t.Fatalf("legacy policy %d does not round-trip", i)
				}
			}

			// Re-encoding the decoded key must be byte-identical.
			if !bytes.Equal(decoded.Bytes(), tt.key.Bytes()) {
				t.Fatalf("marshal round-trip is not byte identical")
			}
		})
	}
}
