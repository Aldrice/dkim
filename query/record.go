package query

import (
	"errors"
	"strings"
)

type TXTRecord struct {
	pfr *PublicKeyFetcher

	tagsMap map[string]string

	version  string
	pk       string
	hashAlg  string
	keyType  string
	srvTypes []string
	flags    []string

	note string
}

func newTXTRecord(pfr *PublicKeyFetcher, hash, key, raw string) (*TXTRecord, error) {
	items := strings.Split(raw, ";")
	mp := make(map[string]string, len(items))
	for _, item := range items {
		pair := strings.SplitN(item, "=", 2)
		if len(pair) != 2 {
			return nil, errors.New("key syntax error")
		}
		k, v := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if k == "" || (k != "p" && v == "") {
			return nil, errors.New("key syntax error")
		}
		mp[k] = v
	}
	return &TXTRecord{pfr: pfr, tagsMap: mp, hashAlg: hash, keyType: key}, nil
}
