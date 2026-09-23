package outbound

import (
	"encoding/base64"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestRealityOptions(t *testing.T) {
	enabled, disabled := true, false
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, value := range []*bool{nil, &enabled, &disabled} {
		config, err := (RealityOptions{PublicKey: key, SupportX25519MLKEM768: value}).Parse()
		if err != nil {
			t.Fatal(err)
		}
		if config.SupportX25519MLKEM768 != (value == nil || *value) {
			t.Fatal("ML-KEM default or explicit value lost")
		}
	}
	public, _ := mldsa65.NewKeyFromSeed(new([mldsa65.SeedSize]byte))
	encoded, _ := public.MarshalBinary()
	config, err := (RealityOptions{PublicKey: key, Mldsa65Verify: base64.RawURLEncoding.EncodeToString(encoded)}).Parse()
	if err != nil || config.Mldsa65Verify == nil {
		t.Fatalf("ML-DSA parse: %v", err)
	}
	for _, opts := range []RealityOptions{
		{PublicKey: key, Mldsa65Verify: "%%%"}, {PublicKey: key, Mldsa65Verify: "YQ"},
		{Mldsa65Verify: "YQ"}, {SupportX25519MLKEM768: &disabled}, {PublicKey: key, ShortID: "abc"}, {PublicKey: "YQ"},
	} {
		if _, err := opts.Parse(); err == nil {
			t.Fatal("malformed REALITY accepted")
		}
	}
}
