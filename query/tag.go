package query

import (
	"dkim/utils"
	"errors"
	"strings"
)

type tagExtractFunc func(rc *TXTRecord, content string) error

type tagExtractor struct {
	name string
	tagExtractFunc
}

var defaultTagExtractors = []tagExtractor{
	{name: "v", tagExtractFunc: version},
	{name: "h", tagExtractFunc: hashAlg},
	{name: "k", tagExtractFunc: keyType},
	{name: "n", tagExtractFunc: note},
	{name: "p", tagExtractFunc: keyData},
	{name: "s", tagExtractFunc: srvType},
	{name: "t", tagExtractFunc: flags},
}

const defaultVersion = "DKIM1"

// version, the tag meaning the Version of the DKIM key record
func version(rc *TXTRecord, content string) error {
	if content == "" {
		rc.version = defaultVersion
	} else {
		if content != rc.pfr.version {
			return errors.New("unsupported DKIM version")
		}
	}
	return nil
}

func hashAlg(rc *TXTRecord, content string) error {
	if content != "" {
		items := strings.Split(content, ":")
		for _, item := range items {
			if rc.hashAlg == strings.TrimSpace(item) {
				return nil
			}
		}
		return errors.New("inappropriate hash algorithm")
	}
	return nil
}

const defaultKeyAlg = "rsa"

func keyType(rc *TXTRecord, content string) error {
	if content == "" {
		rc.keyType = defaultKeyAlg
	} else {
		if rc.keyType != content {
			return errors.New("inappropriate key algorithm")
		}
	}
	return nil
}

func note(rc *TXTRecord, content string) error {
	if content != "" {
		rc.note = content
	}
	return nil
}

// keyData, content is empty meaning this public key had been revoked
func keyData(rc *TXTRecord, content string) error {
	if content == "" {
		return errors.New("key revoked")
	}
	pk := utils.StripWhitespace(content)
	if !utils.Base64Regexp.MatchString(pk) {
		return errors.New("key syntax error")
	}
	rc.pk = pk
	return nil
}

func srvType(rc *TXTRecord, content string) error {
	// todo: only support smtp service
	return nil
}

func flags(rc *TXTRecord, content string) error {
	// todo: implement this
	return nil
}
