package convert_test

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	. "github.com/metacubex/mihomo/common/convert"
	"github.com/stretchr/testify/require"
)

const realityLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@[::1]:443?security=reality&type=xhttp&pbk=ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw&sid=aabb&fp=chrome&sni=upload.test&support-x25519mlkem768=false"

func TestRealityLinkPreservesIndependentDownload(t *testing.T) {
	extra := map[string]any{
		"headers": map[string]any{"X-Upload": "upload"},
		"downloadSettings": map[string]any{
			"address": "::1", "port": 8443, "security": "reality",
			"tlsSettings":     map[string]any{"serverName": "ignored.test", "fingerprint": "ignored"},
			"realitySettings": map[string]any{"publicKey": "ignored", "password": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw", "serverName": "download.test", "fingerprint": "safari", "shortId": "ccdd", "mldsa65Verify": "verification-key", "support-x25519mlkem768": true},
			"xhttpSettings":   map[string]any{"path": "/download", "extra": map[string]any{"headers": map[string]any{"X-Download": "download"}}},
		},
	}
	encoded, err := json.Marshal(extra)
	require.NoError(t, err)
	proxies, err := ConvertsV2Ray([]byte(realityLink + "&pqv=upload-verification-key&extra=" + url.QueryEscape(string(encoded))))
	require.NoError(t, err)
	require.Len(t, proxies, 1)
	proxy := proxies[0]
	require.Equal(t, "::1", proxy["server"])
	require.Equal(t, "upload.test", proxy["servername"])
	reality := proxy["reality-opts"].(map[string]any)
	require.Equal(t, false, reality["support-x25519mlkem768"])
	require.Equal(t, "upload-verification-key", reality["mldsa65-verify"])
	xhttp := proxy["xhttp-opts"].(map[string]any)
	require.Equal(t, map[string]any{"X-Upload": "upload"}, xhttp["headers"])
	download := xhttp["download-settings"].(map[string]any)
	require.Equal(t, "::1", download["server"])
	require.Equal(t, "download.test", download["servername"])
	require.Equal(t, "safari", download["client-fingerprint"])
	require.Equal(t, "/download", download["path"])
	require.Equal(t, map[string]any{"X-Download": "download"}, download["headers"])
	downloadReality := download["reality-opts"].(map[string]any)
	require.Equal(t, "ccdd", downloadReality["short-id"])
	require.Equal(t, true, downloadReality["support-x25519mlkem768"])
	require.Equal(t, "verification-key", downloadReality["mldsa65-verify"])
	require.Equal(t, reality["public-key"], downloadReality["public-key"])
	_, err = adapter.ParseProxy(proxy)
	require.Error(t, err)
	delete(reality, "mldsa65-verify")
	delete(downloadReality, "mldsa65-verify")
	parsed, err := adapter.ParseProxy(proxy)
	require.NoError(t, err)
	parsed.Close()
}

func TestMalformedRealityRejectsWholeSubscription(t *testing.T) {
	for _, query := range []string{
		"&support-x25519mlkem768=wrong", "&extra=%7B", "&extra=null",
		"&extra=" + url.QueryEscape(`{"downloadSettings": false}`),
		"&extra=" + url.QueryEscape(`{"downloadSettings":{"security":"reality","realitySettings":{"password":42}}}`),
		"&extra=" + url.QueryEscape(`{"downloadSettings":{"security":"reality","realitySettings":{}}}`),
		"&extra=" + url.QueryEscape(`{"downloadSettings":{"security":"unknown"}}`),
		"&extra=" + url.QueryEscape(`{"downloadSettings":{"realitySettings":{"password":"ignored"}}}`),
	} {
		t.Run(query, func(t *testing.T) {
			proxies, err := ConvertsV2Ray([]byte(realityLink + "\n" + realityLink + query))
			require.Error(t, err)
			require.Nil(t, proxies)
		})
	}
}
