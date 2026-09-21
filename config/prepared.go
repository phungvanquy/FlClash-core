package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/geodata"
	P "github.com/metacubex/mihomo/constant/provider"
	R "github.com/metacubex/mihomo/rules"
	RP "github.com/metacubex/mihomo/rules/provider"
	T "github.com/metacubex/mihomo/tunnel"
)

type parseContext struct {
	detached          bool
	ruleParser        R.Parser
	proxyNames        []string
	owned             []io.Closer
	activation        []func()
	providerNamespace string
}

func (p *parseContext) providerName(kind, name string) string {
	if p.providerNamespace == "" {
		return name
	}
	return "__flclash_" + p.providerNamespace + "_" + kind + "_" + base64.RawURLEncoding.EncodeToString([]byte(name))
}

func (p *parseContext) own(resource any) {
	if p.detached {
		if closer, ok := resource.(io.Closer); ok {
			p.owned = append(p.owned, closer)
		}
	}
}

func (p *parseContext) deferActivation(activate func()) {
	if p.detached {
		p.activation = append(p.activation, activate)
	} else {
		activate()
	}
}

func (p *parseContext) close() error {
	var errs []error
	for i := len(p.owned) - 1; i >= 0; i-- {
		errs = append(errs, p.owned[i].Close())
	}
	p.owned = nil
	p.activation = nil
	return errors.Join(errs...)
}

type PrepareOptions struct {
	ResolveGeodata    func(name string) (string, error)
	ProviderNamespace string
}

type PreparedConfig struct {
	mu      sync.Mutex
	config  *Config
	context *parseContext
}

func PrepareRawConfig(raw *RawConfig, options PrepareOptions) (*PreparedConfig, error) {
	p := &parseContext{
		detached:          true,
		providerNamespace: options.ProviderNamespace,
		ruleParser: R.Parser{Geodata: geodata.NewScope(geodata.ScopeOptions{
			Mode:    raw.GeodataMode,
			Loader:  raw.GeodataLoader,
			Matcher: raw.GeositeMatcher,
			Resolve: options.ResolveGeodata,
		})},
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = p.close()
		}
	}()
	cfg, err := p.parseRawConfig(raw)
	if err != nil {
		return nil, err
	}
	cfg.GeodataScope = p.ruleParser.Geodata
	prepare := func(pd P.Provider) error {
		loader, ok := pd.(interface{ Prepare() error })
		if !ok {
			return fmt.Errorf("provider %s does not support preparation", pd.Name())
		}
		if err := loader.Prepare(); err != nil {
			return fmt.Errorf("prepare provider %s: %w", pd.Name(), err)
		}
		return nil
	}
	for _, pd := range cfg.Providers {
		if err := prepare(pd); err != nil {
			return nil, err
		}
		if pd.VehicleType() != P.Compatible {
			for _, proxy := range pd.Proxies() {
				p.own(proxy)
			}
		}
	}
	for _, pd := range cfg.RuleProviders {
		if err := prepare(pd); err != nil {
			return nil, err
		}
	}
	accepted = true
	return &PreparedConfig{config: cfg, context: p}, nil
}

func (p *PreparedConfig) Inspect(inspect func(*Config) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.config == nil {
		return errors.New("prepared configuration has been consumed")
	}
	return inspect(p.config)
}

func (p *PreparedConfig) Activate(apply func(*Config)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.config == nil {
		return errors.New("prepared configuration has been consumed")
	}
	cfg := p.config
	if cfg.Profile.StoreFakeIP {
		if cfg.DNS.FakeIPPool != nil {
			pool, err := fakeip.New(fakeip.Options{IPNet: cfg.DNS.FakeIPRange, Persistence: true})
			if err != nil {
				return err
			}
			cfg.DNS.FakeIPPool = pool
		}
		if cfg.DNS.FakeIPPool6 != nil {
			pool, err := fakeip.New(fakeip.Options{IPNet: cfg.DNS.FakeIPRange6, Persistence: true})
			if err != nil {
				return err
			}
			cfg.DNS.FakeIPPool6 = pool
		}
	}
	SetProxyNameList(p.context.proxyNames)
	RP.SetTunnel(T.Tunnel)
	for _, activate := range p.context.activation {
		activate()
	}
	p.context.detached = false
	p.context.owned = nil
	p.context.activation = nil
	p.config = nil
	apply(cfg)
	return nil
}

func (p *PreparedConfig) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config = nil
	return p.context.close()
}
