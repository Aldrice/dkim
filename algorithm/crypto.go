package algorithm

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
)

var DefaultEncryptionMap = setupEncryptionMap()

func setupEncryptionMap() map[string]EncryptAlgorithm {
	mp := make(map[string]EncryptAlgorithm)
	for _, a := range defaultEncryptionList {
		mp[a.Name()] = a
	}
	return mp
}

var defaultEncryptionList = []EncryptAlgorithm{
	new(RSA),
}

type EncryptAlgorithm interface {
	Name() string
	Decrypt(pk, sig, hashed []byte, hash crypto.Hash) error
}

type RSA struct{}

func (r RSA) Decrypt(pk, sig, hashed []byte, hash crypto.Hash) error {
	pub, err := x509.ParsePKIXPublicKey(pk)
	if err != nil {
		return err
	}
	rpk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("key syntax error, not an RSA public key")
	}
	// according to rfc8301 section-3.2, the size of rsa keys should not less than 1024bits
	// otherwise will be more easily compromised to off-line attacks
	// ref: https://datatracker.ietf.org/doc/html/rfc8301#section-3.2
	if rpk.Size()*8 < 1024 {
		return errors.New("key length is shorter than 1024")
	}
	return rsa.VerifyPKCS1v15(rpk, hash, hashed, sig)
}

func (r RSA) Name() string {
	return strings.ToLower(x509.RSA.String())
}
