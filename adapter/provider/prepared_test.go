package provider

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type candidateTracker struct {
	C.Connection
	closed bool
}

func (c *candidateTracker) ID() string                   { return "candidate-preparation-test" }
func (c *candidateTracker) Info() *statistic.TrackerInfo { return &statistic.TrackerInfo{} }
func (c *candidateTracker) ProviderChains() C.Chain      { return C.Chain{"existing-provider"} }
func (c *candidateTracker) Close() error                 { c.closed = true; return nil }

func TestProviderPreparationDoesNotCloseMatchingConnectionsOrStartHealthChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider.yaml")
	if err := os.WriteFile(path, []byte("validated"), 0600); err != nil {
		t.Fatal(err)
	}
	tracker := &candidateTracker{}
	statistic.DefaultManager.Join(tracker)
	t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })
	parses := 0
	proxy := adapter.NewProxy(outbound.NewDirect())
	provider, err := NewProxySetProvider("existing-provider", 0, nil, func(buf []byte) ([]C.Proxy, error) {
		parses++
		return []C.Proxy{proxy}, nil
	}, resource.NewHTTPVehicle("https://example.invalid", path, "", nil, 0, 0), NewHealthCheck(nil, "https://example.invalid", 5000, 300, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	if err := provider.Prepare(); err != nil {
		t.Fatal(err)
	}
	if provider.Count() != 1 || parses != 1 {
		t.Fatal("staged provider was not loaded")
	}
	if provider.started.Load() || tracker.closed {
		t.Fatal("preparation touched live work")
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if tracker.closed {
		t.Fatal("discard closed existing connection")
	}
}

func TestProviderActivationUsesPreparedBytes(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() {
		if cachefile.Cache().DB != nil {
			_ = cachefile.Cache().Close()
		}
		C.SetHomeDir(previousHome)
	})
	path := filepath.Join(t.TempDir(), "provider.yaml")
	if err := os.WriteFile(path, []byte("validated"), 0600); err != nil {
		t.Fatal(err)
	}
	parses := 0
	provider, err := NewProxySetProvider("candidate", 0, nil, func(buf []byte) ([]C.Proxy, error) {
		parses++
		return []C.Proxy{adapter.NewProxy(outbound.NewDirect())}, nil
	}, resource.NewHTTPVehicle("https://example.invalid", path, "", nil, 0, 0), NewHealthCheck(nil, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	if err := provider.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := provider.Initial(); err != nil {
		t.Fatal(err)
	}
	if parses != 1 || provider.Count() != 1 {
		t.Fatal("activation reloaded prepared data")
	}
}

func TestDetachedProviderRejectsDuplicateNames(t *testing.T) {
	parser, err := NewProxiesParser("candidate", nil, "", "", "", "", overrideSchema{}, "", adapter.WithDetached(true))
	if err != nil {
		t.Fatal(err)
	}
	_, err = parser([]byte("proxies:\n  - {name: same, type: socks5, server: 127.0.0.1, port: 1080}\n  - {name: same, type: socks5, server: 127.0.0.1, port: 1081}\n"))
	if err == nil {
		t.Fatal("ambiguous duplicate accepted")
	}
}

func TestPreparedProviderKeepsNativeHealthChecksWithoutContentRefresh(t *testing.T) {
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() {
		if cachefile.Cache().DB != nil {
			_ = cachefile.Cache().Close()
		}
		C.SetHomeDir(previousHome)
	})
	checked := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		select {
		case checked <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "provider.yaml")
	if err := os.WriteFile(path, []byte("committed"), 0600); err != nil {
		t.Fatal(err)
	}
	pd, err := NewProxySetProvider("managed", time.Hour, nil, func([]byte) ([]C.Proxy, error) {
		return []C.Proxy{adapter.NewProxy(outbound.NewDirect())}, nil
	}, resource.NewHTTPVehicle("https://example.invalid", path, "", nil, 0, 0), NewHealthCheck(nil, server.URL, 1000, 300, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pd.Close() })
	if err := pd.Prepare(); err != nil {
		t.Fatal(err)
	}
	if err := pd.Initial(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-checked:
	case <-time.After(3 * time.Second):
		t.Fatal("native health checks did not start")
	}
	if err := pd.Update(); err != resource.ErrManagedRefresh {
		t.Fatalf("content refresh = %v", err)
	}
}
