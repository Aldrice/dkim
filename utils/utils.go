package utils

import (
	"bufio"
	"fmt"
	"net/textproto"
	"regexp"
	"strings"
	"unicode"
)

var DomainRegexp = regexp.MustCompile(`^(?i)[a-z0-9-]+(\.[a-z0-9-]+)+\.?$`)
var Base64Regexp = regexp.MustCompile(`^(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=|[A-Za-z0-9+\\/]{4})$`)

const CRLF = "\r\n"

type HeaderMap map[string][]Header

type Header struct {
	Raw string
	Val string
}

func AbstractHeader(r *bufio.Reader) (HeaderMap, error) {
	// todo: 可能需要检查from是否存在
	tr := textproto.NewReader(r)

	var hs []string
	for {
		l, err := tr.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("failed to read header: %v", err)
		}

		if len(l) == 0 {
			break
		} else if len(hs) > 0 && (l[0] == ' ' || l[0] == '\t') {
			// This is a continuation line
			hs[len(hs)-1] += l + CRLF
		} else {
			hs = append(hs, l+CRLF)
		}
	}

	// todo: temporary solution
	// some headers was allowed to have multiple lines according to https://www.rfc-editor.org/rfc/rfc5322#section-3.6
	ht := make(HeaderMap, len(hs))
	for _, s := range hs {
		kv := strings.SplitN(s, ":", 2)
		var k, v string
		k = strings.ToLower(strings.TrimSpace(kv[0]))
		if len(kv) > 1 {
			v = strings.TrimSpace(kv[1])
		}
		ht[k] = append(ht[k], Header{Raw: s, Val: v})
	}

	return ht, nil
}

func StripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// FixCRLF Fix any \n without a matching \r
func FixCRLF(b []byte) []byte {
	res := make([]byte, 0, len(b))
	for i := range b {
		if b[i] == '\n' && (i == 0 || b[i-1] != '\r') {
			res = append(res, '\r')
		}
		res = append(res, b[i])
	}
	return res
}

func RemoveWS(s string) string {
	return regexp.MustCompile(`[ \t]+`).ReplaceAllString(s, " ")
}
