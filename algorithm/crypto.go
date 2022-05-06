package algorithm

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
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
	new(RSAVerifier),
}

type EncryptAlgorithm interface {
	Name() string
	NewEncryptionVerifier(pk []byte) (EncryptAlgorithm, error)
	IsEmpty() bool
	Verify(sig, hashed []byte, hash crypto.Hash) error
}

type RSAVerifier struct {
	*rsa.PublicKey
}

func (r RSAVerifier) IsEmpty() bool {
	return r.PublicKey != nil
}

func (r RSAVerifier) NewEncryptionVerifier(pk []byte) (EncryptAlgorithm, error) {
	pub, err := x509.ParsePKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	rpk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key syntax error, not an RSA public key")
	}
	// according to rfc8301 section-3.2, the size of rsa keys should not less than 1024bits
	// otherwise will be more easily compromise to off-line attacks
	// ref: https://datatracker.ietf.org/doc/html/rfc8301#section-3.2
	if rpk.Size()*8 < 1024 {
		return nil, errors.New("key length is shorter than 1024")
	}
	return RSAVerifier{PublicKey: rpk}, nil
}

func (r RSAVerifier) Verify(sig, hashed []byte, hash crypto.Hash) error {
	return rsa.VerifyPKCS1v15(r.PublicKey, hash, hashed, sig)
}

func (r RSAVerifier) Name() string {
	return "rsa"
}
