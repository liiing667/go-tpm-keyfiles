package keyfile

import (
	"encoding/asn1"

	"github.com/google/go-tpm/tpm2"
)

type TPMKeyOption func(key *TPMKey)

func WithKeytype(keytype asn1.ObjectIdentifier) TPMKeyOption {
	return func(key *TPMKey) {
		key.Keytype = keytype
	}
}

func WithPolicy(policy []*TPMPolicy) TPMKeyOption {
	return func(key *TPMKey) {
		key.Policy = policy
	}
}

func WithSecret(secret tpm2.TPM2BEncryptedSecret) TPMKeyOption {
	return func(key *TPMKey) {
		key.Secret = secret
	}
}

// WithUserAuth sets the auth value of the key. A nil or empty userauth
// marks the key as emptyAuth; a non-empty userauth clears emptyAuth and
// keeps the value in memory for key creation. The value itself is never
// serialized to the file, only the resulting emptyAuth boolean is.
func WithUserAuth(userauth []byte) TPMKeyOption {
	return func(key *TPMKey) {
		key.EmptyAuth = true
		if len(userauth) != 0 {
			key.userAuth = userauth
			key.EmptyAuth = false
		}
	}
}

func WithDescription(desc string) TPMKeyOption {
	return func(key *TPMKey) {
		key.Description = desc
	}
}

func WithParent(parent tpm2.TPMHandle) TPMKeyOption {
	return func(key *TPMKey) {
		key.Parent = parent
	}
}

func WithAuthPolicy(authpolicy []*TPMAuthPolicy) TPMKeyOption {
	return func(key *TPMKey) {
		key.AuthPolicy = authpolicy
	}
}

func WithPubkey(pubkey tpm2.TPM2BPublic) TPMKeyOption {
	return func(key *TPMKey) {
		key.Pubkey = pubkey
	}
}

func WithPrivkey(privkey tpm2.TPM2BPrivate) TPMKeyOption {
	return func(key *TPMKey) {
		key.Privkey = privkey
	}
}
