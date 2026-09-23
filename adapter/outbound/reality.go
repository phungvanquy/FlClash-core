package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type RealityOptions struct {
	PublicKey string `proxy:"public-key"`
	ShortID   string `proxy:"short-id,omitempty"`

	SupportX25519MLKEM768 *bool  `proxy:"support-x25519mlkem768,omitempty"`
	Mldsa65Verify         string `proxy:"mldsa65-verify,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.SupportX25519MLKEM768 = o.SupportX25519MLKEM768 == nil || *o.SupportX25519MLKEM768
		if o.Mldsa65Verify != "" {
			key, err := base64.RawURLEncoding.DecodeString(o.Mldsa65Verify)
			if err != nil {
				return nil, errors.New("invalid REALITY mldsa65-verify key")
			}
			config.Mldsa65Verify = new(mldsa65.PublicKey)
			if err := config.Mldsa65Verify.UnmarshalBinary(key); err != nil {
				return nil, errors.New("invalid REALITY mldsa65-verify key size")
			}
		}

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		return config, nil
	}
	if o.ShortID != "" || o.Mldsa65Verify != "" || o.SupportX25519MLKEM768 != nil {
		return nil, errors.New("REALITY options require a public-key")
	}
	return nil, nil
}
