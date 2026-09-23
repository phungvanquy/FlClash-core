package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/metacubex/utls"
)

func TestRealityFingerprintKeyShares(t *testing.T) {
	for _, name := range []string{"", "chrome", "firefox", "safari", "chrome120", "firefox120", "safari16", "ios", "android", "edge", "360", "qq"} {
		t.Run(name, func(t *testing.T) {
			id, err := GetRealityFingerprint(name, true)
			if err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			conn, err := newRealityClient(a, &utls.Config{ServerName: "example.test"}, id, true)
			if err != nil {
				t.Fatal(err)
			}
			modern := name != "chrome120" && name != "firefox120" && name != "safari16"
			if err := validateRealityKeyShares(conn.HandshakeState.Hello.KeyShares); (err == nil) != modern {
				t.Fatalf("modern=%t: %v", modern, err)
			}
			if name == "ios" || name == "android" || name == "edge" || name == "360" || name == "qq" || name == "firefox" {
				keys := conn.HandshakeState.State13.KeyShareKeys
				if keys.Ecdhe != nil && !bytes.Equal(keys.Ecdhe.PublicKey().Bytes(), keys.MlkemEcdhe.PublicKey().Bytes()) {
					t.Fatal("hybrid and classical shares use different authentication keys")
				}
			}
			if err := BuildRemovedX25519MLKEM768HandshakeState(conn); err != nil {
				t.Fatal(err)
			}
			for _, share := range conn.HandshakeState.Hello.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					t.Fatal("legacy mode retained hybrid key share")
				}
			}
		})
	}
	for range 100 {
		id, err := GetRealityFingerprint("random", true)
		if err != nil {
			t.Fatal(err)
		}
		eligible := false
		for _, name := range realityFingerprints {
			eligible = eligible || id == fingerprints[name]
		}
		if !eligible {
			t.Fatalf("ineligible random fingerprint %v", id)
		}
	}
	if _, err := GetRealityFingerprint("invalid", true); err == nil {
		t.Fatal("unknown fingerprint accepted")
	}
	if _, ok := GetFingerprint(""); ok {
		t.Fatal("generic TLS default changed")
	}
	if Get, _ := GetFingerprint("random"); Get != randomFingerprint() {
		t.Fatal("generic TLS random selection changed")
	}
}

func TestRealityKeyShareValidation(t *testing.T) {
	hybrid := utls.KeyShare{Group: utls.X25519MLKEM768, Data: make([]byte, 1216)}
	classical := utls.KeyShare{Group: utls.X25519, Data: make([]byte, 32)}
	for _, shares := range [][]utls.KeyShare{nil, {classical}, {classical, hybrid}, {hybrid, hybrid}, {hybrid, classical, classical}, {{Group: utls.X25519MLKEM768, Data: make([]byte, 32)}}} {
		if err := validateRealityKeyShares(shares); err == nil {
			t.Fatal("invalid shares accepted")
		}
	}
	for _, shares := range [][]utls.KeyShare{{hybrid}, {hybrid, classical}} {
		if err := validateRealityKeyShares(shares); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRealityAdaptationDoesNotChangeOrdinaryTLS(t *testing.T) {
	for _, name := range []string{"ios", "android", "edge", "360", "qq"} {
		t.Run(name, func(t *testing.T) {
			id, _ := GetRealityFingerprint(name, true)
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			if _, err := newRealityClient(conn, &utls.Config{ServerName: "example.test"}, id, true); err != nil {
				t.Fatal(err)
			}
			generic, _ := GetFingerprint(name)
			if generic != id {
				t.Fatal("ordinary TLS fingerprint mapping changed")
			}
			ordinary := utls.UClient(conn, &utls.Config{ServerName: "example.test"}, generic)
			if err := ordinary.BuildHandshakeState(); err != nil {
				t.Fatal(err)
			}
			for _, share := range ordinary.HandshakeState.Hello.KeyShares {
				if share.Group == utls.X25519MLKEM768 {
					t.Fatal("REALITY adaptation modified the ordinary TLS preset")
				}
			}
		})
	}
}

func TestRealityMLDSAVerification(t *testing.T) {
	var seed [mldsa65.SeedSize]byte
	public, private := mldsa65.NewKeyFromSeed(&seed)
	for _, name := range []string{"valid", "wrong-key", "wrong-transcript", "missing-signature", "malformed-signature", "missing-handshake", "omitted", "no-certificate", "nil-certificate"} {
		t.Run(name, func(t *testing.T) {
			verifier := &realityVerifier{authKey: []byte("synthetic-auth-key"), mldsa65Verify: public}
			verifier.UConn = &utls.UConn{HandshakeState: utls.PubClientHandshakeState{Hello: &utls.PubClientHelloMsg{Raw: []byte("client")}, ServerHello: &utls.PubServerHelloMsg{Raw: []byte("server")}}}
			cert := &x509.Certificate{PublicKey: ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))}
			hash := hmac.New(sha512.New, verifier.authKey)
			hash.Write(cert.PublicKey.(ed25519.PublicKey))
			cert.Signature = hash.Sum(nil)
			hash.Write(verifier.HandshakeState.Hello.Raw)
			hash.Write(verifier.HandshakeState.ServerHello.Raw)
			signature := make([]byte, mldsa65.SignatureSize)
			if err := mldsa65.SignTo(private, hash.Sum(nil), nil, false, signature); err != nil {
				t.Fatal(err)
			}
			cert.Extensions = []pkix.Extension{{Value: signature}}
			state := utls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			switch name {
			case "wrong-key":
				seed[0] = 1
				verifier.mldsa65Verify, _ = mldsa65.NewKeyFromSeed(&seed)
			case "wrong-transcript":
				verifier.HandshakeState.Hello.Raw = []byte("different")
			case "missing-signature":
				cert.Extensions = nil
			case "malformed-signature":
				cert.Extensions[0].Value = []byte("short")
			case "missing-handshake":
				verifier.UConn = nil
			case "omitted":
				verifier.mldsa65Verify = nil
				cert.Extensions = nil
			case "no-certificate":
				state.PeerCertificates = nil
			case "nil-certificate":
				state.PeerCertificates[0] = nil
			}
			err := verifier.VerifyConnection(state)
			want := name == "valid" || name == "omitted"
			if (err == nil) != want || verifier.verified != want {
				t.Fatalf("verified=%t error=%v", verifier.verified, err)
			}
		})
	}
}
