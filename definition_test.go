package dkim

import (
	"dkim/utils"
	"testing"
)

func TestDomainRegexp(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"1", "example.com", true},
		{"2", "example..com", false},
		{"3", "xn--0zwm56d.com", true},
		{"4", ".example.com", false},
		{"5", "qq.example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := utils.DomainRegexp.MatchString(tt.raw)
			if rs != tt.want {
				t.Errorf("exception result, want()=%v, got()=%v", tt.want, rs)
			}
		})
	}
}
