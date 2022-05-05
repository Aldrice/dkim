package dkim

// Signer for DKIM Version 1
type Signer struct {
}

func NewSigner() *Signer {
	v := &Signer{}
	return v
}
