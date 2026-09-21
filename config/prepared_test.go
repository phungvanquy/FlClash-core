package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
	"google.golang.org/protobuf/proto"
)

func candidate(t *testing.T, extra string) *config.RawConfig {
	t.Helper()
	raw, err := config.UnmarshalRawConfig([]byte(`mode: direct
ipv6: true
interface-name: candidate-interface
routing-mark: 123
geodata-loader: standard
proxies:
  - {name: Candidate, type: socks5, server: 127.0.0.1, port: 1080}
` + extra))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeGeoSite(t *testing.T) string {
	t.Helper()
	buf, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{
		CountryCode: "TEST",
		Domain:      []*router.Domain{{Type: router.Domain_Full, Value: "example.test"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "GeoSite.dat")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDetachedParsePreservesLiveStateDuringLateFailure(t *testing.T) {
	oldMode, oldNames := tunnel.Mode(), config.GetProxyNameList()
	oldIPv6, oldInterface, oldMark := resolver.DisableIPv6, dialer.DefaultInterface.Load(), dialer.DefaultRoutingMark.Load()
	t.Cleanup(func() {
		tunnel.SetMode(oldMode)
		config.SetProxyNameList(oldNames)
		resolver.DisableIPv6 = oldIPv6
		dialer.DefaultInterface.Store(oldInterface)
		dialer.DefaultRoutingMark.Store(oldMark)
	})
	tunnel.SetMode(tunnel.Rule)
	config.SetProxyNameList([]string{"Existing"})
	resolver.DisableIPv6 = true
	dialer.DefaultInterface.Store("existing-interface")
	dialer.DefaultRoutingMark.Store(42)
	oldLoader, oldMatcher, oldGeoMode := geodata.LoaderName(), geodata.SiteMatcherName(), geodata.GeodataMode()
	assertLive := func() {
		t.Helper()
		if tunnel.Mode() != tunnel.Rule || !resolver.DisableIPv6 || dialer.DefaultInterface.Load() != "existing-interface" || dialer.DefaultRoutingMark.Load() != 42 {
			t.Fatal("candidate changed live routing settings")
		}
		if !reflect.DeepEqual(config.GetProxyNameList(), []string{"Existing"}) {
			t.Fatal("candidate published proxy names")
		}
		if geodata.LoaderName() != oldLoader || geodata.SiteMatcherName() != oldMatcher || geodata.GeodataMode() != oldGeoMode {
			t.Fatal("candidate changed global geodata settings")
		}
	}
	path := writeGeoSite(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	raw := candidate(t, "rules:\n  - GEOSITE,test,Candidate\n  - INVALID-RULE,example.test,Candidate\n")
	go func() {
		_, err := config.PrepareRawConfig(raw, config.PrepareOptions{ResolveGeodata: func(string) (string, error) { close(entered); <-release; return path, nil }})
		finished <- err
	}()
	<-entered
	assertLive()
	close(release)
	err := <-finished
	if err == nil || !strings.Contains(err.Error(), "INVALID-RULE") {
		t.Fatalf("expected late rule rejection, got %v", err)
	}
	assertLive()
}

func TestPreparedConfigPublishesOnlyOnActivationAndConsumesOnce(t *testing.T) {
	oldNames := config.GetProxyNameList()
	t.Cleanup(func() { config.SetProxyNameList(oldNames) })
	config.SetProxyNameList([]string{"Existing"})
	prepared, err := config.PrepareRawConfig(candidate(t, "rules:\n  - MATCH,Candidate\n"), config.PrepareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = prepared.Close() })
	if !reflect.DeepEqual(config.GetProxyNameList(), []string{"Existing"}) {
		t.Fatal("preparation published names")
	}
	if err := prepared.Inspect(func(cfg *config.Config) error {
		if cfg.Proxies["Candidate"] == nil || len(cfg.Rules) != 1 {
			return errors.New("candidate is incomplete")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	applied := false
	if err := prepared.Activate(func(cfg *config.Config) {
		applied = true
		if !reflect.DeepEqual(config.GetProxyNameList(), []string{"DIRECT", "REJECT", "Candidate"}) {
			t.Error("activation did not publish names")
		}
		for _, proxy := range cfg.Proxies {
			_ = proxy.Close()
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatal("activation did not apply")
	}
	if err := prepared.Activate(func(*config.Config) { t.Error("activated twice") }); err == nil {
		t.Fatal("consumed handle accepted")
	}
}

func TestDiscardedConfigCannotActivate(t *testing.T) {
	prepared, err := config.PrepareRawConfig(candidate(t, "rules:\n  - MATCH,Candidate\n"), config.PrepareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Activate(func(*config.Config) { t.Error("discarded candidate activated") }); err == nil {
		t.Fatal("discarded handle accepted")
	}
}

func TestDetachedDNSAndNestedRulesUseCandidateGeoData(t *testing.T) {
	path := writeGeoSite(t)
	requests := 0
	prepared, err := config.PrepareRawConfig(candidate(t, `rules:
  - 'AND,((GEOSITE,test),(DOMAIN-SUFFIX,test)),Candidate'
dns:
  enable: true
  nameserver: [1.1.1.1]
  nameserver-policy:
    'geosite:test': [1.1.1.1]
  enhanced-mode: fake-ip
  fake-ip-filter: ['geosite:test']
`), config.PrepareOptions{ResolveGeodata: func(name string) (string, error) {
		requests++
		if name != C.GeositeName {
			return "", errors.New("unexpected resource")
		}
		return path, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if requests != 1 {
		t.Fatalf("candidate matcher cache missed: %d requests", requests)
	}
	if err := prepared.Inspect(func(cfg *config.Config) error {
		matched, target := cfg.Rules[0].Match(&C.Metadata{Host: "example.test"}, C.RuleMatchHelper{})
		if !matched || target != "Candidate" {
			return errors.New("nested rule did not retain candidate geodata")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestScopedGeodataRefreshPreservesPrivateGenerationAndFailedMatches(t *testing.T) {
	for _, loader := range []string{"standard", "memconservative"} {
		t.Run(loader, func(t *testing.T) {
			original := writeGeoSite(t)
			originalBytes, err := os.ReadFile(original)
			if err != nil {
				t.Fatal(err)
			}
			scope := geodata.NewScope(geodata.ScopeOptions{Loader: loader, Resolve: func(string) (string, error) { return original, nil }})
			if _, err := scope.LoadGeoSiteMatcher("test"); err != nil {
				t.Fatal(err)
			}
			previous := geodata.ActiveScope()
			geodata.SetActiveScope(scope)
			t.Cleanup(func() { geodata.SetActiveScope(previous) })
			if !geodata.GeoSiteEnable() {
				t.Fatal("active private geodata was omitted from automatic updates")
			}
			updated := filepath.Join(t.TempDir(), "GeoSite.dat")
			buf, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "TEST", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "updated.test"}}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(updated, buf, 0600); err != nil {
				t.Fatal(err)
			}
			if err := scope.Refresh("GeoSite.dat", updated); err != nil {
				t.Fatal(err)
			}
			matcher, err := scope.LoadGeoSiteMatcher("test")
			if err != nil || !matcher.ApplyDomain("updated.test") || matcher.ApplyDomain("example.test") {
				t.Fatalf("updated matcher not adopted: %v", err)
			}
			if err := os.WriteFile(updated, []byte("invalid database"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := scope.Refresh("GeoSite.dat", updated); err == nil {
				t.Fatal("invalid refresh accepted")
			}
			matcher, err = scope.LoadGeoSiteMatcher("test")
			if err != nil || !matcher.ApplyDomain("updated.test") {
				t.Fatal("failed refresh erased the usable matcher")
			}
			after, err := os.ReadFile(original)
			if err != nil || !reflect.DeepEqual(after, originalBytes) {
				t.Fatal("refresh changed immutable generation bytes")
			}
		})
	}
}
