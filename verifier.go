package dkim

import (
	"bufio"
	"context"
	"crypto"
	"crypto/subtle"
	"dkim/algorithm"
	"dkim/query"
	. "dkim/utils"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

const verifierPrefix = "DKIM"
const defaultDKIMTimeout = time.Second * 10

func NewVerifier() (*Verifier, error) {
	return &Verifier{
		hashMap:         algorithm.DefaultHashMap,
		encryptionMap:   algorithm.DefaultEncryptionMap,
		canonicalizeMap: algorithm.DefaultCanonicalizeAlgorithm,
		fetcher:         query.NewPublicKeyFetcher(verifierPrefix + version),

		ctx:     context.TODO(),
		version: version,
		timeout: defaultDKIMTimeout,

		tagVerifiersList: defaultTagExtractorList,
	}, nil
}

// Verifier for DKIM Version 1
// todo: add setter
type Verifier struct {
	// algorithms map
	hashMap         map[string]algorithm.HashAlgorithm
	encryptionMap   map[string]algorithm.EncryptAlgorithm
	canonicalizeMap map[string]algorithm.CanonicalizeAlgorithm

	// verifier setting
	ctx     context.Context
	version string
	timeout time.Duration

	// verifier component
	tagVerifiersList []TagExtractor
	fetcher          *query.PublicKeyFetcher
}

func (v *Verifier) SetTimeout(t time.Duration) {
	v.timeout = t
}

func (v *Verifier) SetResolver(r *net.Resolver) {
	v.fetcher.SetResolver(r)
}

type Message struct {
	content    *bufio.Reader
	headersMap HeaderMap
	signatures []*Signature
}

func NewMessage(v *Verifier, r io.Reader) (*Message, error) {
	br := bufio.NewReader(r)
	hm, err := AbstractHeader(br)
	if err != nil {
		return nil, err
	}

	m := &Message{
		content:    br,
		headersMap: hm,
	}

	sigs, ok := m.headersMap[strings.ToLower(SignatureKey)]
	if len(sigs) > 0 {
		m.signatures = make([]*Signature, len(sigs))
		if ok {
			for i, h := range sigs {
				m.signatures[i] = NewSignature(h).SetVerifier(v).SetMessage(m)
			}
		}
	} else {
		m.signatures = []*Signature{}
	}

	return m, nil
}

// VerificationGenerator used to generate verification header to store verify result
// Ref: https://datatracker.ietf.org/doc/html/rfc6376#section-6
type VerificationGenerator struct {
}

func (v *Verifier) Validate(ctx context.Context, r io.Reader) ([]*Signature, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	v.ctx = ctx
	defer cancel()

	// todo: wrap the error
	msg, err := NewMessage(v, r)
	if err != nil {
		return nil, err
	}

	if len(msg.signatures) == 0 {
		return msg.signatures, nil
	}
	for _, s := range msg.signatures {
		if err := v.extractTags(s); err != nil {
			s.verification = generateVerification(err)
			if s.verification.status == StatusPermFail {
				continue
			}
		}

		if err := v.getPublicKey(s); err != nil {
			s.verification = generateVerification(err)
			if s.verification.status == StatusPermFail {
				continue
			}
		}

		if err := v.computeSignature(s); err != nil {
			s.verification = generateVerification(err)
			if s.verification.status == StatusPermFail {
				continue
			}
		}

		// todo: generate verification for each signature
	}
	return msg.signatures, nil
}

func generateVerification(err error) Verification {
	tErr := err.(*DError)
	return Verification{
		status:  tErr.status,
		message: tErr.message,
	}
}

const (
	FromKey      = "From"
	SignatureKey = "DKIM-Signature"
)

func (v *Verifier) extractTags(s *Signature) error {
	for _, vfr := range v.tagVerifiersList {
		t, ok := s.GetTagMap()[vfr.Name()]
		if !ok {
			if vfr.IsRequired(s) {
				return NewDkimError(StatusPermFail, "signature missing required tag")
			}
		} else {
			if err := vfr.Extract(s, t); err != nil {
				return err
			}
		}
	}
	return nil
}

// todo: 还未实现真正意义上的循环验证
func (v *Verifier) getPublicKey(s *Signature) (err error) {
	// acquire public key
	var ks []string
	var pk string
	var tempErr error
	for _, qm := range s.queryMethod {
		items := strings.SplitN(qm, "/", 2)
		qt, ok := v.fetcher.GetTypeMap()[items[0]]
		if !ok {
			continue
		} else {
			option := ""
			if len(items) == 2 {
				option = items[1]
			}
			target := &net.DNSError{}
			ks, err = qt.QueryPublicKey(v.ctx, option, s.domain, s.selector)
			if err == nil {
				for _, k := range ks {
					temp, err2 := v.fetcher.ExtractTxtRecord(s.HashAlgorithm.Name(), s.EncryptAlgorithm.Name(), k)
					if err2 == nil {
						pk = temp
						tempErr = nil
					}
				}
				break
			} else if errors.As(err, &target) {
				tempErr = err
			}
		}
	}
	if tempErr != nil {
		return WrapError(tempErr, StatusTempFail, "key unavailable")
	}
	if pk == "" {
		return NewDkimError(StatusPermFail, "no key for signature")
	}

	// store the public key
	// todo: temp solution
	b, err := base64.StdEncoding.DecodeString(pk)
	if err != nil {
		return WrapError(err, StatusPermFail, "failed to decode public key from base64 format")
	}

	s.EncryptAlgorithm, err = s.EncryptAlgorithm.Init(b)
	if err != nil {
		return WrapError(err, StatusPermFail, "exception occurred when parsing the public key")
	}

	return nil
}

func (v *Verifier) computeSignature(s *Signature) error {
	var hash crypto.Hash
	hash = s.HashAlgorithm.Hash()

	// verify body hash
	hr := hash.New()
	var w io.Writer = hr
	if s.bodyLength >= 0 {
		w = &algorithm.LimitedWriter{W: w, N: s.bodyLength}
	}
	wc := s.body.CanonicalizeBody(w)
	// todo: may take this error as temp fail
	if _, err := io.Copy(wc, s.message.content); err != nil {
		return WrapError(err, StatusPermFail, "an exception occurred when input the content")
	}
	if err := wc.Close(); err != nil {
		return WrapError(err, StatusPermFail, "an exception occurred when closing the writer")
	}
	bh, err := base64.StdEncoding.DecodeString(s.bodyHash)
	if err != nil {
		return WrapError(err, StatusPermFail, "an exception occurred when decoding the bh string")
	}
	if subtle.ConstantTimeCompare(hr.Sum(nil), bh) != 1 {
		return NewDkimError(StatusPermFail, "body hash did not verify")
	}

	// compute the hash and validate the signature
	hr.Reset()
	for _, h := range s.declaredHeaders {
		h, ok := s.message.headersMap[strings.ToLower(h)]
		if !ok {
			continue
		}
		for _, item := range h {
			_, err := hr.Write([]byte(s.header.CanonicalizeHeader(item.Raw)))
			if err != nil {
				return WrapError(err, StatusPermFail, "failed to write canonicalize header into hash")
			}
		}
	}

	// todo: find the relative definition in the rfc document
	// remove signature encryption cipher in the 'b=' tag of signature header
	// than press it into queue prepare for compute
	sf := s.body.CanonicalizeHeader(removeCipher(s.raw))
	sf = strings.TrimRight(sf, CRLF)
	if _, err := hr.Write([]byte(sf)); err != nil {
		return WrapError(err, StatusPermFail, "failed to write canonicalize signature field into hash")
	}

	bc, err := base64.StdEncoding.DecodeString(s.bodyCipher)
	if err != nil {
		return WrapError(err, StatusPermFail, "failed to decode body cipher from base64 format")
	}

	if err := s.EncryptAlgorithm.Verify(bc, hr.Sum(nil), hash); err != nil {
		return WrapError(err, StatusPermFail, "signature did not verify")
	}

	return nil
}

func removeCipher(s string) string {
	return regexp.MustCompile(`(b\s*=)[^;]+`).ReplaceAllString(s, "$1")
}

/*
已经实现的要求:
	Tag验证阶段
	ref: https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.1
	1. 当'v='标签不符合当前DKIM版本时, 返回PERMFAIL (incompatible version), 可忽略该签名也可强行验证; 采用忽略签名
	2. 当缺少必要的tag时, 返回PERMFAIL (signature missing required tag), 且忽略掉该签名
	3. 若'h='标签未包含From标头, 则返回PERMFAIL (From field not signed), 并且忽略掉该签名
	4. DKIM头在语义或结构方面的错误必须严格处理, 返回PERMFAIL (signature syntax error), 并且忽略掉该签名
	5. 若'i='标签不存在, 则将其值视为'@d', 其中d来自'd='标签的值
	6. 若'i='标签存在, 但是其值的根域不等于'd='标签的值, 则返回PERMFAIL (domain mismatch), 并且忽略掉该签名
	7. 若'd='标签其值无效, 可以忽略该签名
	8. 验证器可以返回PERMFAIL (unacceptable signature header), 并且忽略掉该签名; 当该签名触犯了某些非法规则
	9. 'h='tag中声明的header序列将会被顺序载入到hash实体中
	10.'h='tag中可能存在被声明但实际不存在的header, 这些header将不参与签名流程
	11.'h='tag中可能存在多个同一header的声明, 这意味着每当该header被声明时, 对应的内容应当被载入到hash实体中

	获取公钥阶段
	ref: https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.2
	1. 当根据获取函数获得到的公钥信息不符合要求的规范时, 直接否认该结果
	2. 检查器通过f(q,d,s)获取公钥信息
	3. 若获取公钥的尝试没有得到响应, 则返回TEMPFAIL (key unavailable), 并推迟对该DKIM签名的验证
	4. 若获取公钥的尝试因没有有效结果而失败, 则返回PERMFAIL (no key for signature), 并认定该签名无效
	6. 若获得到的公钥信息不符合规范, 则返回PERMFAIL (key syntax error),
	7. 若获得到的公钥其声明的版本(v=)没有被验证器实现, 则同样返回6中的错误
	8. 若公钥信息中含有(h=, 指明hash算法), 而签名中声明的算法中不包含其中, 则返回PERMFAIL (inappropriate hash algorithm)
	9. 若公钥信息中的公钥(p=)为空, 则表明该密钥对已经被放弃, 则返回PERMFAIL (key revoked)
	10.若获得到的公钥无法正确验证, 则返回PERMFAIL (inappropriate key algorithm)

	公钥验证阶段
	ref: https://datatracker.ietf.org/doc/html/rfc6376#section-6.1.3
	1. 根据DKIM签名中的'c=', 'h=', 'l='等tag的值去生成一个规范化后的邮件, 生成的内容应当另外缓存起来
	2. 当匹配邮件header name的时候, 应当用字母大小写不敏感的匹配方式进行匹配
	3. 根据'a='tag中指明的哈希算法, 去计算规范化后邮件的哈希值, 并且与'bh='标签中的值进行比较, 不匹配则返回PERMFAIL (body hash did not verify)
	4. 根据'b='tag中提供的签名序列, 结合'a='tag中描述的加密策略, 去验证该签名的有效性, 无效则返回PERMFAIL (signature did not verify)
	5. 计算或验证签名时, 必须将签名中'b='tag的值视为空
*/

/*
todo:
	控制验证次数, 防止denial-of-service攻击
	ref: https://datatracker.ietf.org/doc/html/rfc6376#section-6.1

*/

/*
todo:
		若'x='标签存在, 且签名已经过期, 则可以返回PERMFAIL (signature expired), 并忽略掉该签名
*/

/*
todo:
		5. 若获得到了多个公钥, 可只取其中一个进行验证, 也可以循环验证
*/
