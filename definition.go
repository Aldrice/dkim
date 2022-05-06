package dkim

import (
	"dkim/algorithm"
	. "dkim/utils"
	"errors"
	"math/big"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

type Status string

const (
	StatusPermFail Status = "permfail"
	StatusTempFail Status = "tempfail"
)

// Verification todo: 完善相关细节, 参考go-dkim
type Verification struct {
	// The SDID claiming responsibility for an introduction of a message into the
	// mail stream.
	Domain string
	// The Agent or User Identifier (AUID) on behalf of which the SDID is taking
	// responsibility.
	Identifier string

	// The time that this signature was created. If unknown, it's set to zero.
	Time time.Time
	// The expiration time. If the signature doesn't expire, it's set to zero.
	Expiration time.Time

	// storing the status of verification
	status Status
	// message storing the fail reason if status is not empty
	message string
}

type Signature struct {
	verifier *Verifier
	message  *Message

	raw    string
	tagMap TagMap

	identifier      string
	domain          string
	signedAt        time.Time
	expiredAt       time.Time
	declaredHeaders []string
	copiedHeaders   []string
	queryMethod     []string
	bodyCipher      string
	bodyHash        string
	// this number is digit-limited, maximum digit width is 76.
	bodyLength *big.Int
	selector   string

	// algorithms
	algorithm.HashAlgorithm
	algorithm.EncryptAlgorithm
	header algorithm.CanonicalizeAlgorithm
	body   algorithm.CanonicalizeAlgorithm

	// todo: verification would be generate with the info of signature itself
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

func (s *Signature) SetVerification(vfc Verification) {
	s.verification = vfc
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
	new(SignedAtTagExtractor),
	new(ExpiredAtTagExtractor),
	new(CopiedTagExtractor),
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
	if s.identifier != "" {
		// todo: s.identifier may be equal or the subdomain of content
		items := strings.SplitN(s.identifier, "@", 2)
		if !strings.HasSuffix(items[1], content) {
			return NewSyntaxError(errors.New("domain mismatch"))
		}
	} else {
		s.identifier = "@" + content
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
// The syntax of identifier is a standard email address where the local-part MAY be omitted.
func (i IdentityTagExtractor) Extract(s *Signature, content string) error {
	items := strings.SplitN(content, "@", 2)
	if len(items) != 2 {
		return NewSyntaxError(errors.New("invalid syntax of identifier"))
	}

	// verify the whole identifier if the local-domain wasn't omitted
	// otherwise only verify the domain part
	if items[0] != "" {
		_, err := mail.ParseAddress(content)
		if err != nil {
			return NewSyntaxError(err)
		}
	}

	// todo: temporary solution, complete design definition see: https://datatracker.ietf.org/doc/html/rfc6376#page-21
	if s.identifier != "" {
		d := items[1]
		if !DomainRegexp.MatchString(d) {
			return NewSyntaxError(errors.New("invalid syntax of identifier"))
		}
		temp := strings.TrimLeft(s.identifier, "@")
		if !strings.HasSuffix(d, temp) {
			return NewSyntaxError(
				errors.New("domain mismatch"),
			)
		}
	}
	s.identifier = content
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
	s.bodyLength = nil
	return false
}

func (l LengthTagExtractor) Extract(s *Signature, content string) error {
	if len(content) > 76 {
		return NewDkimError(StatusPermFail, "invalid length, this figure should not longer than 76 digits")
	}
	length, ok := new(big.Int).SetString(content, 10)
	if !ok {
		return NewSyntaxError(errors.New("decimal syntax error"))
	}
	s.bodyLength = length
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

type SignedAtTagExtractor struct{}

func (st SignedAtTagExtractor) Name() string {
	return "t"
}

func (st SignedAtTagExtractor) IsRequired(s *Signature) bool {
	s.signedAt = time.Time{}
	return false
}

func (st SignedAtTagExtractor) Extract(s *Signature, content string) error {
	t, err := parseTimestamp(content)
	if err != nil {
		return WrapError(err, StatusPermFail, "error occurred when parsing the timestamp")
	}
	if t.After(time.Now()) {
		return NewDkimError(StatusPermFail, "invalid timestamp, declared timestamp is in the future")
	}
	if !s.expiredAt.IsZero() && t.After(s.expiredAt) {
		return NewDkimError(StatusPermFail, "invalid timestamp, signed time after the expired time")
	}
	s.signedAt = t
	return nil
}

type ExpiredAtTagExtractor struct{}

func (e ExpiredAtTagExtractor) Name() string {
	return "x"
}

func (e ExpiredAtTagExtractor) IsRequired(s *Signature) bool {
	s.expiredAt = time.Time{}
	return false
}

func (e ExpiredAtTagExtractor) Extract(s *Signature, content string) error {
	t, err := parseTimestamp(content)
	if err != nil {
		return WrapError(err, StatusPermFail, "error occurred when parsing the timestamp")
	}
	// The value of the "x=" tag MUST be greater than the value of the "t=" tag if both are present.
	// ref: https://datatracker.ietf.org/doc/html/rfc6376#page-24
	if !s.signedAt.IsZero() && s.signedAt.After(t) {
		return NewDkimError(StatusPermFail, "invalid timestamp, signed time after the expired time")
	}
	if s.message.receiveTime.After(t) {
		return NewDkimError(StatusPermFail, "signature expired")
	}
	s.expiredAt = t
	return nil
}

type CopiedTagExtractor struct{}

func (c CopiedTagExtractor) Name() string {
	return "z"
}

func (c CopiedTagExtractor) IsRequired(_ *Signature) bool {
	return false
}

func (c CopiedTagExtractor) Extract(s *Signature, content string) error {
	s.copiedHeaders = strings.Split(StripWhitespace(content), "|")
	return nil
}

func parseTimestamp(raw string) (time.Time, error) {
	et := time.Time{}
	// according to rfc document, implementation should be prepared to handle values up to 10^12(12 digits)
	// any timestamp longer than 12 digits would be taken as infinite in order to avoid denial-of-service attacks
	// ref: https://datatracker.ietf.org/doc/html/rfc6376#page-24
	if len(raw) > 12 {
		return et, errors.New("number digit more than 12")
	}
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return et, errors.New("invalid timestamp syntax")
	}
	return time.Unix(ts, 0), nil
}
