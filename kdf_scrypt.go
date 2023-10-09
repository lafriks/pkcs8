package pkcs8

import (
	"encoding/asn1"

	"golang.org/x/crypto/scrypt"
)

var oidScrypt = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}

func init() {
	RegisterKDF(oidScrypt, func() KDFParameters {
		return new(scryptParams)
	})
}

type scryptParams struct {
	Salt                     []byte
	CostParameter            int
	BlockSize                int
	ParallelizationParameter int
}

func (p scryptParams) DeriveKey(password []byte, size int) ([]byte, error) {
	return scrypt.Key(password, p.Salt, p.CostParameter, p.BlockSize,
		p.ParallelizationParameter, size)
}

// ScryptOpts contains options for the scrypt key derivation function.
type ScryptOpts struct {
	SaltSize                 int
	CostParameter            int
	BlockSize                int
	ParallelizationParameter int
}

// DeriveKey derives a key of size bytes from the given password and salt.
func (p ScryptOpts) DeriveKey(password, salt []byte, keyLen int) (
	[]byte, KDFParameters, error,
) {
	key, err := scrypt.Key(password, salt, p.CostParameter, p.BlockSize,
		p.ParallelizationParameter, keyLen)
	if err != nil {
		return nil, nil, err
	}
	params := scryptParams{
		BlockSize:                p.BlockSize,
		CostParameter:            p.CostParameter,
		ParallelizationParameter: p.ParallelizationParameter,
		Salt:                     salt,
	}
	return key, params, nil
}

// GetSaltSize returns the salt size.
func (p ScryptOpts) GetSaltSize() int {
	return p.SaltSize
}

// OID returns the OID of scrypt.
func (p ScryptOpts) OID() asn1.ObjectIdentifier {
	return oidScrypt
}
