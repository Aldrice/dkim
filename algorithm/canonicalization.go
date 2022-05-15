package algorithm

import (
	. "dkim/utils"
	"io"
	"strings"
)

// todo: 联系原作者, 问问他关于此部分内容的态度

var DefaultCanonicalizeAlgorithm = func() map[string]CanonicalizeAlgorithm {
	m := map[string]CanonicalizeAlgorithm{}
	for _, ca := range defaultCanonicalizationList {
		m[ca.Name()] = ca
	}
	return m
}()

var defaultCanonicalizationList = []CanonicalizeAlgorithm{
	new(simpleCanonicalizeAlgorithm),
	new(relaxedCanonicalizeAlgorithm),
}

// A CanonicalizeAlgorithm contains 2 parts which processing header or body part
// ref: https://datatracker.ietf.org/doc/html/rfc6376#section-3.4
type CanonicalizeAlgorithm interface {
	Name() string
	CanonicalizeHeader(s string) string
	CanonicalizeBody(w io.Writer) io.WriteCloser
}

type simpleCanonicalizeAlgorithm struct{}

func (sa simpleCanonicalizeAlgorithm) Name() string {
	return "simple"
}

// CanonicalizeHeader used to canonicalize the header content
// simple canonicalize algorithm will not change header content in any way
// ref: https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.1
func (sa simpleCanonicalizeAlgorithm) CanonicalizeHeader(s string) string {
	return s
}

type simpleBodyCanonicalizer struct {
	w       io.Writer
	crlfBuf []byte
}

func (c *simpleBodyCanonicalizer) Write(b []byte) (int, error) {
	written := len(b)
	b = append(c.crlfBuf, b...)

	b = FixCRLF(b)

	end := len(b)
	// If it ends with \r, maybe the next write will begin with \n
	if end > 0 && b[end-1] == '\r' {
		end--
	}
	// Keep all \r\n sequences
	for end >= 2 {
		prev := b[end-2]
		cur := b[end-1]
		if prev != '\r' || cur != '\n' {
			break
		}
		end -= 2
	}

	c.crlfBuf = b[end:]

	var err error
	if end > 0 {
		_, err = c.w.Write(b[:end])
	}
	return written, err
}

func (c *simpleBodyCanonicalizer) Close() error {
	// Flush crlfBuf if it ends with a single \r (without a matching \n)
	if len(c.crlfBuf) > 0 && c.crlfBuf[len(c.crlfBuf)-1] == '\r' {
		if _, err := c.w.Write(c.crlfBuf); err != nil {
			return err
		}
	}
	c.crlfBuf = nil

	if _, err := c.w.Write([]byte(CRLF)); err != nil {
		return err
	}
	return nil
}

func (sa simpleCanonicalizeAlgorithm) CanonicalizeBody(w io.Writer) io.WriteCloser {
	return &simpleBodyCanonicalizer{w: w}
}

type relaxedCanonicalizeAlgorithm struct{}

func (r relaxedCanonicalizeAlgorithm) Name() string {
	return "relaxed"
}

// CanonicalizeHeader used to canonicalize the header content
// relaxed canonicalize algorithm will convert the content with 5 steps in a specific order
// ref: https://datatracker.ietf.org/doc/html/rfc6376#section-3.4.2
func (r relaxedCanonicalizeAlgorithm) CanonicalizeHeader(s string) string {
	kv := strings.SplitN(s, ":", 2)
	k := strings.TrimSpace(strings.ToLower(kv[0]))
	v := strings.ReplaceAll(kv[1], "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.TrimSpace(RemoveWS(v))
	return k + ":" + v + CRLF
}

type relaxedBodyCanonicalizer struct {
	w       io.Writer
	crlfBuf []byte
	wspBuf  []byte
	written bool
}

func (c *relaxedBodyCanonicalizer) Write(b []byte) (int, error) {
	written := len(b)

	b = FixCRLF(b)

	canonical := make([]byte, 0, len(b))
	for _, ch := range b {
		if ch == ' ' || ch == '\t' {
			c.wspBuf = append(c.wspBuf, ch)
		} else if ch == '\r' || ch == '\n' {
			c.wspBuf = nil
			c.crlfBuf = append(c.crlfBuf, ch)
		} else {
			if len(c.crlfBuf) > 0 {
				canonical = append(canonical, c.crlfBuf...)
				c.crlfBuf = nil
			}
			if len(c.wspBuf) > 0 {
				canonical = append(canonical, ' ')
				c.wspBuf = nil
			}

			canonical = append(canonical, ch)
		}
	}

	if !c.written && len(canonical) > 0 {
		c.written = true
	}

	_, err := c.w.Write(canonical)
	return written, err
}

func (c *relaxedBodyCanonicalizer) Close() error {
	if c.written {
		if _, err := c.w.Write([]byte(CRLF)); err != nil {
			return err
		}
	}
	return nil
}

func (r relaxedCanonicalizeAlgorithm) CanonicalizeBody(w io.Writer) io.WriteCloser {
	return &relaxedBodyCanonicalizer{w: w}
}

type LimitedWriter struct {
	W io.Writer
	N int64
}

func (w *LimitedWriter) Write(b []byte) (int, error) {
	if w.N <= 0 {
		return len(b), nil
	}

	skipped := 0
	if int64(len(b)) > w.N {
		b = b[:w.N]
		skipped = int(int64(len(b)) - w.N)
	}

	n, err := w.W.Write(b)
	w.N -= int64(n)
	return n + skipped, err
}
