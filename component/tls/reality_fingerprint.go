package tls

import (
	"net"
	"slices"

	utls "github.com/metacubex/utls"
)

func newRealityClient(conn net.Conn, config *utls.Config, fingerprint UClientHelloID, modern bool) (*utls.UConn, error) {
	client := utls.UClient(conn, config, fingerprint)
	if modern && (fingerprint == fingerprints["ios"] || fingerprint == fingerprints["android"] ||
		fingerprint == fingerprints["edge"] || fingerprint == fingerprints["360"] || fingerprint == fingerprints["qq"]) {
		spec, err := utls.UTLSIdToSpec(fingerprint)
		if err != nil {
			return nil, err
		}
		modernizeRealitySpec(&spec)
		client = utls.UClient(conn, config, utls.HelloCustom)
		if err := client.ApplyPreset(&spec); err != nil {
			return nil, err
		}
	}
	if err := client.BuildHandshakeState(); err != nil {
		return nil, err
	}
	return client, nil
}

// These legacy browser presets need adapted TLS extensions for modern REALITY;
// their resulting ClientHello is not an exact historical browser fingerprint.
func modernizeRealitySpec(spec *utls.ClientHelloSpec) {
	spec.TLSVersMin, spec.TLSVersMax = utls.VersionTLS12, utls.VersionTLS13
	if !slices.Contains(spec.CipherSuites, utls.TLS_AES_128_GCM_SHA256) {
		spec.CipherSuites = append([]uint16{utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256}, spec.CipherSuites...)
	}
	shares, versions, modes, alpn := false, false, false, false
	keyShares := utls.ReuseHybridAndClassicalKeyShares(utls.KeyShare{Group: utls.X25519MLKEM768}, utls.KeyShare{Group: utls.X25519})
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			index := 0
			if len(extension.Curves) > 0 && extension.Curves[0] == utls.GREASE_PLACEHOLDER {
				index = 1
			}
			extension.Curves = slices.Insert(extension.Curves, index, utls.X25519MLKEM768)
			if !slices.Contains(extension.Curves, utls.X25519) {
				extension.Curves = slices.Insert(extension.Curves, index+1, utls.X25519)
			}
		case *utls.KeyShareExtension:
			shares = true
			prefix := extension.KeyShares[:0]
			for _, share := range extension.KeyShares {
				if share.Group == utls.GREASE_PLACEHOLDER {
					prefix = append(prefix, share)
				}
			}
			extension.KeyShares = append(prefix, keyShares...)
		case *utls.SupportedVersionsExtension:
			versions = true
		case *utls.PSKKeyExchangeModesExtension:
			modes = true
		case *utls.ALPNExtension:
			alpn = true
			extension.AlpnProtocols = []string{"h2", "http/1.1"}
		case *utls.SignatureAlgorithmsExtension:
			if !slices.Contains(extension.SupportedSignatureAlgorithms, utls.PSSWithSHA256) {
				extension.SupportedSignatureAlgorithms = append([]utls.SignatureScheme{utls.PSSWithSHA256, utls.PSSWithSHA384, utls.PSSWithSHA512}, extension.SupportedSignatureAlgorithms...)
			}
		}
	}
	if !shares {
		spec.Extensions = append(spec.Extensions, &utls.KeyShareExtension{KeyShares: keyShares})
	}
	if !versions {
		spec.Extensions = append(spec.Extensions, &utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}})
	}
	if !modes {
		spec.Extensions = append(spec.Extensions, &utls.PSKKeyExchangeModesExtension{Modes: []uint8{utls.PskModeDHE}})
	}
	if !alpn {
		spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}})
	}
}
