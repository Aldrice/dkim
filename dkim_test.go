package dkim

import (
	"bytes"
	"context"
	"dkim/utils"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func TestTrimSpace(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"1", "\t\nabc\t\n"},
		{"2", "\t\nabc   "},
		{"2", "  a b c   "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := utils.StripWhitespace(tt.raw)
			b := strings.TrimSpace(tt.raw)
			fmt.Println(a)
			fmt.Println(b)
		})
	}
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name        string
		contentPath string
		want        *Verifier
		wantErr     bool
	}{
		{name: "1", contentPath: "./testdata/email_content_1.txt", want: nil, wantErr: false},
		{name: "2", contentPath: "./testdata/email_content_2.txt", want: nil, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := ioutil.ReadFile(tt.contentPath)
			if err != nil {
				return
			}
			v, err := NewVerifier(bytes.NewReader(content))
			if (err != nil) != tt.wantErr {
				t.Errorf("failed to get verifier")
				return
			}
			_, err = v.Validate(context.Background())
			if err != nil {
				t.Errorf("failed to validate signatures")
				return
			}
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("NewVerifier() got = %v, want %v", got, tt.want)
			//}
		})
	}
}
