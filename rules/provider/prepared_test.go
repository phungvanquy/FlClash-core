package provider

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/resource"
	P "github.com/metacubex/mihomo/constant/provider"
)

type candidateTunnel struct {
	P.Tunnel
	publications int
}

func (c *candidateTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	c.publications++
	return utils.NewCallback[P.RuleProvider]()
}

func TestDetachedRuleProviderDoesNotPublishOrRefetch(t *testing.T) {
	previous := tunnel
	live := &candidateTunnel{}
	SetTunnel(live)
	t.Cleanup(func() { SetTunnel(previous) })
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("payload:\n  - example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pd := NewRuleSetProvider("candidate", P.Domain, P.YamlRule, 0, resource.NewHTTPVehicle("https://example.invalid", path, "", nil, 0, 0), nil, nil, nil).(*RuleSetProvider)
	t.Cleanup(func() { _ = pd.Close() })
	if err := pd.Prepare(); err != nil {
		t.Fatal(err)
	}
	if pd.Count() != 1 || live.publications != 0 {
		t.Fatal("candidate not loaded privately")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := pd.Initial(); err != nil {
		t.Fatal(err)
	}
	if pd.Count() != 1 || live.publications != 0 {
		t.Fatal("activation reloaded candidate")
	}
}
