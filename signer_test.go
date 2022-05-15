package dkim

import (
	"reflect"
	"testing"
)

func TestNewSigner(t *testing.T) {
	tests := []struct {
		name string
		want *Signer
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewSigner(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}
