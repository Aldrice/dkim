package query

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// todo: make PublicFetcher can be set in using specific DNS resolver

type PublicKeyFetcher struct {
	version       string
	typeMap       map[string]PKQueryType
	tagExtractors []tagExtractor
}

func NewPublicKeyFetcher(version string) *PublicKeyFetcher {
	return &PublicKeyFetcher{
		typeMap:       defaultTypeMap,
		version:       version,
		tagExtractors: defaultTagExtractors,
	}
}

func (p *PublicKeyFetcher) SetResolver(r *net.Resolver) {
	for _, t := range p.typeMap {
		t.SetResolver(r)
	}
}

func (p *PublicKeyFetcher) ExtractTxtRecord(hash, key, content string) (string, error) {
	rc, err := newTXTRecord(p, hash, key, content)
	if err != nil {
		return "", err
	}
	for _, er := range p.tagExtractors {
		v, _ := rc.tagsMap[er.name]
		if err2 := er.tagExtractFunc(rc, v); err2 != nil {
			return "", err2
		}
	}
	return rc.pk, nil
}

func (p *PublicKeyFetcher) GetTypeMap() map[string]PKQueryType {
	return p.typeMap
}

var defaultTypeMap = func() map[string]PKQueryType {
	tMaps := map[string]PKQueryType{
		"dns": new(DNSQueryType),
	}
	for _, t := range tMaps {
		t.Init()
		t.SetResolver(net.DefaultResolver)
	}
	return tMaps
}()

// PKQueryType
// Type/Options
type PKQueryType interface {
	Init()
	SetResolver(r *net.Resolver)
	GetResolver() *net.Resolver
	QueryPublicKey(ctx context.Context, o, d, s string) ([]string, error)
}

type DNSQueryType struct {
	optionMap map[string]OptionFunc
	*net.Resolver
}

func (dq *DNSQueryType) Init() {
	dq.optionMap = map[string]OptionFunc{
		"txt": txtOption,
	}
}

func (dq *DNSQueryType) SetResolver(r *net.Resolver) {
	dq.Resolver = r
}

func (dq *DNSQueryType) GetResolver() *net.Resolver {
	return dq.Resolver
}

func (dq DNSQueryType) QueryPublicKey(ctx context.Context, o, d, s string) ([]string, error) {
	of, ok := dq.optionMap[o]
	if !ok {
		return nil, errors.New("unsupported option in type 'dns'")
	}
	return of(ctx, &dq, d, s)
}

type OptionFunc func(ctx context.Context, pkq PKQueryType, d, s string) ([]string, error)

const keySubDomainName = "_domainKey"

func txtOption(ctx context.Context, pkq PKQueryType, d, s string) ([]string, error) {
	txt, err := pkq.GetResolver().LookupTXT(ctx, fmt.Sprintf("%s.%s.%s", s, keySubDomainName, d))
	if err != nil {
		return nil, err
	}
	return txt, nil
}
