package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

const RealityMaxShortIDLen = 8

var realityCompatibilityVersion = [3]byte{26, 3, 27}

var realityFingerprints = [...]string{"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq"}

type RealityConfig struct {
	PublicKey *ecdh.PublicKey
	ShortID   [RealityMaxShortIDLen]byte

	SupportX25519MLKEM768 bool
	Mldsa65Verify         *mldsa65.PublicKey
}

func GetRealityFingerprint(name string, modern bool) (UClientHelloID, error) {
	if name == "" {
		name = "chrome"
	}
	if modern && name == "random" {
		name = realityFingerprints[randv2.IntN(len(realityFingerprints))]
	}
	fingerprint, ok := GetFingerprint(name)
	if !ok {
		return UClientHelloID{}, fmt.Errorf("unsupported REALITY client-fingerprint %q", name)
	}
	return fingerprint, nil
}

func validateRealityKeyShares(shares []utls.KeyShare) error {
	hybrid, classical := 0, 0
	for _, share := range shares {
		switch share.Group {
		case utls.X25519MLKEM768:
			if classical != 0 || len(share.Data) != 1216 {
				return errors.New("invalid REALITY hybrid key-share order or size")
			}
			hybrid++
		case utls.X25519:
			classical++
		}
	}
	if hybrid != 1 || classical > 1 {
		return errors.New("REALITY requires one X25519MLKEM768 key share before optional X25519")
	}
	return nil
}

func GetRealityConn(ctx context.Context, conn net.Conn, fingerprint UClientHelloID, serverName string, realityConfig *RealityConfig) (net.Conn, error) {
	for retry := 0; ; retry++ {
		verifier := &realityVerifier{
			serverName:    serverName,
			mldsa65Verify: realityConfig.Mldsa65Verify,
		}
		uConfig := &utls.Config{
			Time:                   ntp.Now,
			ServerName:             serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			VerifyConnection:       verifier.VerifyConnection,
		}

		uConn, err := newRealityClient(conn, uConfig, fingerprint, realityConfig.SupportX25519MLKEM768)
		if err != nil {
			return nil, err
		}
		verifier.UConn = uConn

		if !realityConfig.SupportX25519MLKEM768 { // for X25519MLKEM768 does not work properly with the old reality server
			err = BuildRemovedX25519MLKEM768HandshakeState(uConn)
			if err != nil {
				return nil, err
			}
		} else if err := validateRealityKeyShares(uConn.HandshakeState.Hello.KeyShares); err != nil {
			return nil, fmt.Errorf("REALITY client-fingerprint %s-%s: %w; use chrome, firefox or safari, or explicit support-x25519mlkem768: false for a legacy server", fingerprint.Client, fingerprint.Version, err)
		}

		hello := uConn.HandshakeState.Hello
		rawSessionID := hello.Raw[39 : 39+32] // the location of session ID
		for i := range rawSessionID {         // https://github.com/golang/go/issues/5373
			rawSessionID[i] = 0
		}

		copy(hello.SessionId, realityCompatibilityVersion[:])
		hello.SessionId[3] = 0
		binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(ntp.Now().Unix()))
		copy(hello.SessionId[8:], realityConfig.ShortID[:])

		keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
		if keyShareKeys == nil {
			if retry > 2 {
				return nil, errors.New("nil keyShareKeys")
			}
			continue // retry
		}
		ecdheKey := keyShareKeys.Ecdhe
		if ecdheKey == nil {
			ecdheKey = keyShareKeys.MlkemEcdhe
		}
		if ecdheKey == nil {
			if retry > 2 {
				return nil, errors.New("nil ecdheKey")
			}
			continue // retry
		}
		authKey, err := ecdheKey.ECDH(realityConfig.PublicKey)
		if err != nil {
			return nil, err
		}
		if authKey == nil {
			return nil, errors.New("nil auth_key")
		}
		verifier.authKey = authKey
		_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
		if err != nil {
			return nil, err
		}
		aesBlock, _ := aes.NewCipher(authKey)
		aeadCipher, _ := cipher.NewGCM(aesBlock)
		aeadCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)

		err = uConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}

		log.Debugln("REALITY Authentication: %v, AEAD: %T", verifier.verified, aeadCipher)

		if !verifier.verified {
			go realityClientFallback(uConn, uConfig.ServerName, fingerprint)
			return nil, errors.New("REALITY authentication failed")
		}

		return uConn, nil
	}
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	// use h2c mode to disallow the net/http fallback to http1.1
	//
	// Note that this usage is only applicable to our own net/http fork.
	// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext
	// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
			Protocols: protocols,
		},
	}
	request, err := http.NewRequest("GET", "https://"+serverName, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", randv2.IntN(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	time.Sleep(time.Duration(5+randv2.IntN(10)) * time.Second)
	response.Body.Close()
	client.CloseIdleConnections()
}

type realityVerifier struct {
	*utls.UConn
	serverName    string
	authKey       []byte
	verified      bool
	mldsa65Verify *mldsa65.PublicKey
}

func (c *realityVerifier) VerifyConnection(state utls.ConnectionState) error {
	certs := state.PeerCertificates
	if len(certs) == 0 || certs[0] == nil {
		return errors.New("REALITY server supplied no certificate")
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			if c.mldsa65Verify != nil {
				if len(certs[0].Extensions) == 0 || c.UConn == nil || c.HandshakeState.Hello == nil || c.HandshakeState.ServerHello == nil {
					return errors.New("REALITY ML-DSA-65 verification data is missing")
				}
				h.Write(c.HandshakeState.Hello.Raw)
				h.Write(c.HandshakeState.ServerHello.Raw)
				if !mldsa65.Verify(c.mldsa65Verify, h.Sum(nil), nil, certs[0].Extensions[0].Value) {
					return errors.New("REALITY ML-DSA-65 verification failed")
				}
			}
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   ntp.Now(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}
