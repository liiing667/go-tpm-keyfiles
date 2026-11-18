package keyfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Errors returned when selecting an auth policy from a TPMKey.
var (
	// ErrNoAuthPolicy is returned when no auth policy matches the selection.
	ErrNoAuthPolicy = errors.New("no auth policy matching selection")
	// ErrAmbiguousAuthPolicy is returned when a selection matches several
	// distinct policy sets, and picking one would be ambiguous.
	ErrAmbiguousAuthPolicy = errors.New("ambiguous auth policy selection")
	// ErrEmptyAuthPolicy is returned when a policy set has no policy items.
	ErrEmptyAuthPolicy = errors.New("auth policy has no policy items")
)

// Equal compares two TPMPolicy items by command code and policy bytes.
func (p *TPMPolicy) Equal(o *TPMPolicy) bool {
	if p == nil || o == nil {
		return p == o
	}
	return p.CommandCode == o.CommandCode && bytes.Equal(p.CommandPolicy, o.CommandPolicy)
}

// Equal compares two policy sets by name and their ordered policy items.
func (a *TPMAuthPolicy) Equal(o *TPMAuthPolicy) bool {
	if a == nil || o == nil {
		return a == o
	}
	if a.Name != o.Name || len(a.Policy) != len(o.Policy) {
		return false
	}
	for i := range a.Policy {
		if !a.Policy[i].Equal(o.Policy[i]) {
			return false
		}
	}
	return true
}

// Digest computes the identity of the policy set.
//
// The identity is the TPM policy hash of the set: starting from the
// all-zero SHA-256 digest, every item extends it as
//
//	digest = SHA-256(digest || commandCode || commandPolicy)
//
// mirroring how a TPM extends policyDigest for each policy command. Two
// policy sets share an authorization path if and only if their identities
// are equal; sets with the same command codes but different policy bytes
// have distinct identities.
//
// An empty policy set has no identity and fails closed with
// ErrEmptyAuthPolicy.
func (a *TPMAuthPolicy) Digest() ([]byte, error) {
	if a == nil || len(a.Policy) == 0 {
		return nil, ErrEmptyAuthPolicy
	}
	digest := make([]byte, sha256.Size)
	var cc [4]byte
	for _, p := range a.Policy {
		if p == nil {
			return nil, ErrEmptyAuthPolicy
		}
		h := sha256.New()
		h.Write(digest)
		binary.BigEndian.PutUint32(cc[:], uint32(p.CommandCode))
		h.Write(cc[:])
		h.Write(p.CommandPolicy)
		digest = h.Sum(nil)
	}
	return digest, nil
}

// SelectAuthPolicy selects a single policy set from the key by name.
//
// Selection is by identity, never by slice position:
//
//   - A key with no auth policies yields (nil, nil); callers fall back to
//     the legacy Policy field or password auth.
//   - A legacy key with only Policy set yields that single unnamed set when
//     selected with an empty name.
//   - An empty name selects the sole policy set of the key. If the key
//     carries several sets the selection is ambiguous and fails closed.
//   - A non-empty name selects the sets with a matching Name. Duplicated
//     names are only accepted when every match is identical (same
//     authorization path); matches with distinct content, such as equal
//     command codes with different digests, fail closed with
//     ErrAmbiguousAuthPolicy.
//   - Any empty policy set in the key fails closed with ErrEmptyAuthPolicy.
func (t *TPMKey) SelectAuthPolicy(name string) (*TPMAuthPolicy, error) {
	if len(t.AuthPolicy) == 0 {
		if len(t.Policy) == 0 {
			return nil, nil
		}
		if name != "" {
			return nil, fmt.Errorf("%w: %q", ErrNoAuthPolicy, name)
		}
		return &TPMAuthPolicy{Policy: t.Policy}, nil
	}

	for _, a := range t.AuthPolicy {
		if a == nil || len(a.Policy) == 0 {
			return nil, ErrEmptyAuthPolicy
		}
	}

	if name == "" {
		if len(t.AuthPolicy) == 1 {
			return t.AuthPolicy[0], nil
		}
		return nil, fmt.Errorf("%w: %d unnamed policy sets", ErrAmbiguousAuthPolicy, len(t.AuthPolicy))
	}

	var match *TPMAuthPolicy
	for _, a := range t.AuthPolicy {
		if a.Name != name {
			continue
		}
		if match == nil {
			match = a
			continue
		}
		if !match.Equal(a) {
			return nil, fmt.Errorf("%w: %q", ErrAmbiguousAuthPolicy, name)
		}
	}
	if match == nil {
		return nil, fmt.Errorf("%w: %q", ErrNoAuthPolicy, name)
	}
	return match, nil
}
