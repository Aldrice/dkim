package dkim

import (
	"dkim/algorithm"
	. "dkim/utils"
	"errors"
	"net/mail"
	"strings"
)

type Status string

const (
	StatusPermFail Status = "permfail"
	StatusTempFail Status = "tempfail"
)

// Verification todo: 完善相关细节, 参考go-dkim
type Verification struct {
	status  Status
	message string
}

type Signature struct {
	verifier *Verifier
	message  *Message

	raw    string
	tagMap TagMap

	identity        string
	domain          string
	declaredHeaders []string
	queryMethod     []string
	bodyCipher      string
	bodyHash        string
	// todo: this number is digit-limited, maximum digit width is 76.
	bodyLength int64
	selector   string

	// algorithms
	algorithm.HashAlgorithm
	algorithm.EncryptAlgorithm
	header algorithm.CanonicalizeAlgorithm
	body   algorithm.CanonicalizeAlgorithm

	verification Verification
}

type TagMap map[string]string

func NewSignature(item Header) *Signature {
	rawTags := strings.Split(item.Val, ";")
	tm := make(TagMap, len(rawTags))
	for _, rt := range rawTags {
		items := strings.SplitN(rt, "=", 2)
		k, v := items[0], ""
		if len(items) == 2 {
			v = items[1]
		}
		tm[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return &Signature{tagMap: tm, raw: item.Raw}
}

func (s *Signature) SetVerifier(vfr *Verifier) *Signature {
	s.verifier = vfr
	return s
}

func (s *Signature) SetMessage(msg *Message) *Signature {
	s.message = msg
	return s
}

func (s *Signature) GetTagMap() TagMap {
	return s.tagMap
}

func (s *Signature) SetVerification(sts Verification) {
	s.verification = sts
}

var defaultTagExtractorList = []TagExtractor{
	new(VersionTagExtractor),
	new(HeaderTagExtractor),
	new(DomainTagExtractor),
	new(IdentityTagExtractor),
	new(AlgorithmTagExtractor),
	new(CanonicalTagExtractor),
	new(BodyTagExtractor),
	new(BodyHashExtractor),
	new(SelectorTagExtractor),
	new(LengthTagExtractor),
	new(QueryMethodTagExtractor),
}

type TagExtractor interface {
	Name() string
	IsRequired(s *Signature) bool
	Extract(s *Signature, content string) error
}

type VersionTagExtractor struct{}

func (v VersionTagExtractor) Name() string {
	return "v"
}

func (v VersionTagExtractor) IsRequired(_ *Signature) bool {
	return true
}

func (v VersionTagExtractor) Extract(s *Signature, content string) error {
	if s.verifier.version != content {
		return NewDkimError(StatusPermFail, "incompatible version")
	}
	return nil
}

type HeaderTagExtractor struct{}

func (h HeaderTagExtractor) Name() string {
	return "h"
}

func (h HeaderTagExtractor) IsRequired(_ *Signature) bool {
	return true
}

// Extract used to verify 'h' tag content
// Header field names MUST be compared against actual header field names in a case-insensitive manner
func (h HeaderTagExtractor) Extract(s *Signature, content string) error {
	headers := strings.Split(content, ":")
	if len(headers) == 0 {
		return NewSyntaxError(errors.New("empty h tag is not allowed"))
	}

	s.declaredHeaders = make([]string, len(headers))
	fromExist := false
	for i, header := range headers {
		header = strings.TrimSpace(header)
		if !fromExist && strings.EqualFold(header, FromKey) {
			fromExist = true
		}
		// todo: not finished yet, still have some situation need to implement
		if strings.EqualFold(header, SignatureKey) {
			return NewSyntaxError(errors.New("dkim signature key was not acceptable in h tag"))
		}

		s.declaredHeaders[i] = header
	}
	if !fromExist {
		return NewSyntaxError(errors.New("from field not signed"))
	}

	return nil
}

type DomainTagExtractor struct{}

func (d DomainTagExtractor) Name() string {
	return "d"
}

func (d DomainTagExtractor) IsRequired(_ *Signature) bool {
	return true
}

func (d DomainTagExtractor) Extract(s *Signature, content string) error {
	if !DomainRegexp.MatchString(content) {
		return NewSyntaxError(errors.New("invalid domain format"))
	}
	s.domain = content
	if s.identity != "" {
		// todo: s.identity may be equal or the subdomain of content
		items := strings.SplitN(s.identity, "@", 2)
		if !strings.HasSuffix(items[1], content) {
			return NewSyntaxError(errors.New("domain mismatch"))
		}
	} else {
		s.identity = "@" + content
	}
	return nil
}

type IdentityTagExtractor struct{}

func (i IdentityTagExtractor) Name() string {
	return "i"
}

func (i IdentityTagExtractor) IsRequired(_ *Signature) bool {
	return false
}

// Extract
// The syntax of identity is a standard email address where the local-part MAY be omitted.
func (i IdentityTagExtractor) Extract(s *Signature, content string) error {
	items := strings.SplitN(content, "@", 2)
	if len(items) != 2 {
		return NewSyntaxError(errors.New("invalid syntax of identity"))
	}

	// verify the whole identity if the local-domain wasn't omitted
	// otherwise only verify the domain part
	if items[0] != "" {
		_, err := mail.ParseAddress(content)
		if err != nil {
			return NewSyntaxError(err)
		}
	}

	if s.identity != "" {
		d := items[1]
		if !DomainRegexp.MatchString(d) {
			return NewSyntaxError(errors.New("invalid syntax of identity"))
		}
		temp := strings.TrimLeft(s.identity, "@")
		if !strings.HasSuffix(d, temp) {
			return NewSyntaxError(
				errors.New("domain mismatch"),
			)
		}
	}
	s.identity = content
	return nil
}

type AlgorithmTagExtractor struct{}

func (a AlgorithmTagExtractor) Name() string {
	return "a"
}

func (a AlgorithmTagExtractor) IsRequired(*Signature) bool {
	return true
}

func (a AlgorithmTagExtractor) Extract(s *Signature, content string) error {
	als := strings.SplitN(content, "-", 2)
	if len(als) != 2 {
		return NewSyntaxError(errors.New("invalid algorithms"))
	}
	var ok bool
	s.EncryptAlgorithm, ok = s.verifier.encryptionMap[als[0]]
	if !ok {
		return NewSyntaxError(errors.New("unsupported encryption algorithm"))
	}
	s.HashAlgorithm, ok = s.verifier.hashMap[als[1]]
	if !ok {
		return NewSyntaxError(errors.New("unsupported hash algorithm"))
	}
	if reason, y := s.HashAlgorithm.IsAbandoned(); y {
		return NewSyntaxError(errors.New("abandoned hash algorithm: " + reason))
	}
	return nil
}

const defaultCanonicalizeType = "simple"

type CanonicalTagExtractor struct{}

func (c CanonicalTagExtractor) Name() string {
	return "c"
}

func (c CanonicalTagExtractor) IsRequired(s *Signature) bool {
	cAlg := s.verifier.canonicalizeMap[defaultCanonicalizeType]
	s.header, s.body = cAlg, cAlg
	return false
}

// Extract
// If only one algorithm is named, that algorithm is used for the header
// and "simple" is used for the body.
func (c CanonicalTagExtractor) Extract(s *Signature, content string) error {
	ts := strings.SplitN(content, "/", 2)
	var ok bool
	switch len(ts) {
	case 2:
		s.header, ok = s.verifier.canonicalizeMap[ts[0]]
		if !ok {
			return NewSyntaxError(errors.New("unsupported canonicalization type"))
		}
		s.body, ok = s.verifier.canonicalizeMap[ts[1]]
		if !ok {
			return NewSyntaxError(errors.New("unsupported canonicalization type"))
		}
	case 1:
		s.header, ok = s.verifier.canonicalizeMap[ts[0]]
		if !ok {
			return NewSyntaxError(errors.New("unsupported canonicalization type"))
		}
		s.body = s.verifier.canonicalizeMap["simple"]
	default:
		return NewSyntaxError(errors.New("invalid canonicalization tag value"))
	}
	return nil
}

type BodyTagExtractor struct{}

func (b BodyTagExtractor) Name() string {
	return "b"
}

func (b BodyTagExtractor) IsRequired(_ *Signature) bool {
	return true
}

// Extract
// Whitespace is ignored in this value and MUST be ignored when reassembling the original signature.
func (b BodyTagExtractor) Extract(s *Signature, content string) error {
	content = StripWhitespace(content)
	if !Base64Regexp.MatchString(content) {
		return NewSyntaxError(errors.New("invalid content in 'b=' tag value"))
	}
	s.bodyCipher = content
	return nil
}

type BodyHashExtractor struct{}

func (bh BodyHashExtractor) Name() string {
	return "bh"
}

func (bh BodyHashExtractor) IsRequired(_ *Signature) bool {
	return true
}

// Extract
// The hash of canonicalize body part of the message as limited by the "l=" tag (base64; REQUIRED).
func (bh BodyHashExtractor) Extract(s *Signature, content string) error {
	content = StripWhitespace(content)
	if !Base64Regexp.MatchString(content) {
		return NewSyntaxError(errors.New("invalid content in 'b=' tag value"))
	}
	s.bodyHash = content
	return nil
}

type SelectorTagExtractor struct{}

func (sr SelectorTagExtractor) Name() string {
	return "s"
}

func (sr SelectorTagExtractor) IsRequired(_ *Signature) bool {
	return true
}

func (sr SelectorTagExtractor) Extract(s *Signature, content string) error {
	s.selector = strings.TrimSpace(content)
	if s.selector == "" {
		return NewSyntaxError(errors.New("invalid content in 's=' tag value"))
	}
	return nil
}

type LengthTagExtractor struct{}

func (l LengthTagExtractor) Name() string {
	return "l"
}

func (l LengthTagExtractor) IsRequired(s *Signature) bool {
	s.bodyLength = -1
	return false
}

func (l LengthTagExtractor) Extract(s *Signature, content string) error {
	//TODO implement me
	return nil
}

type QueryMethodTagExtractor struct{}

func (q QueryMethodTagExtractor) Name() string {
	return "q"
}

func (q QueryMethodTagExtractor) IsRequired(s *Signature) bool {
	s.queryMethod = []string{"dns/txt"}
	return false
}

// Extract
// query method with the form of 'type/[options]'
func (q QueryMethodTagExtractor) Extract(s *Signature, content string) error {
	if content != "" {
		s.queryMethod = strings.Split(content, ":")
	}
	return nil
}

// todo: t, x, z
