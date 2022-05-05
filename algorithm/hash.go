package algorithm

import (
	"crypto"
)

var DefaultHashMap = func() map[string]HashAlgorithm {
	mp := make(map[string]HashAlgorithm)
	for _, a := range defaultHashList {
		mp[a.Name()] = a
	}
	return mp
}()

var defaultHashList = []HashAlgorithm{
	new(SHA1),
	new(SHA256),
}

type HashAlgorithm interface {
	Hash() crypto.Hash
	IsAbandoned() (string, bool)
	Name() string
}

type SHA1 struct{}

func (S SHA1) IsAbandoned() (string, bool) {
	return "this algorithm is not safe anymore", true
}

func (S SHA1) Name() string {
	return "sha1"
}

// Deprecated: an unsafe hash algorithm
func (S SHA1) Hash() crypto.Hash {
	return crypto.SHA1
}

type SHA256 struct{}

func (S SHA256) IsAbandoned() (string, bool) {
	return "", false
}

func (S SHA256) Name() string {
	return "sha256"
}

func (S SHA256) Hash() crypto.Hash {
	return crypto.SHA256
}
