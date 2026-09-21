package geodata

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/oschwald/maxminddb-golang"
)

type ScopeOptions struct {
	Mode    bool
	Loader  string
	Matcher string
	Resolve func(name string) (string, error)
}

type Scope struct {
	options   ScopeOptions
	mu        sync.Mutex
	paths     map[string]string
	sites     map[string]router.DomainMatcher
	ips       map[string]router.IPMatcher
	ipReader  *mmdb.IPReader
	asnReader *mmdb.ASNReader
}

func NewScope(options ScopeOptions) *Scope {
	return &Scope{options: options, paths: make(map[string]string), sites: make(map[string]router.DomainMatcher), ips: make(map[string]router.IPMatcher)}
}

var activeScope atomic.Pointer[Scope]

func ActiveScope() *Scope { return activeScope.Load() }

func SetActiveScope(scope *Scope) {
	activeScope.Store(scope)
	if scope != nil {
		scope.mu.Lock()
		defer scope.mu.Unlock()
		geoSiteEnable.Store(len(scope.sites) != 0)
		geoIpEnable.Store(len(scope.ips) != 0 || scope.ipReader != nil)
		asnEnable.Store(scope.asnReader != nil)
	}
}

func (s *Scope) GeodataMode() bool { return s.options.Mode }

func (s *Scope) loader() (Loader, error) {
	name := s.options.Loader
	if name == "memc" {
		name = "memconservative"
	}
	return GetGeoDataLoader(name)
}

func (s *Scope) resolve(name string) (string, error) {
	if path, ok := s.paths[name]; ok {
		return path, nil
	}
	if s.options.Resolve == nil {
		return "", fmt.Errorf("missing candidate geodata resolver for %s", name)
	}
	return s.options.Resolve(name)
}

func (s *Scope) LoadGeoSiteMatcher(country string) (router.DomainMatcher, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if matcher, ok := s.sites[country]; ok {
		return matcher, nil
	}
	key := strings.ToLower(country)
	not := strings.HasPrefix(key, "!")
	key = strings.TrimPrefix(key, "!")
	parts := strings.Split(key, "@")
	list := strings.TrimSpace(parts[0])
	if list == "" {
		return nil, fmt.Errorf("empty geosite list")
	}
	path, err := s.resolve("GeoSite.dat")
	if err != nil {
		return nil, err
	}
	loader, err := s.loader()
	if err != nil {
		return nil, err
	}
	domains, err := loader.LoadSiteByPath(path, list)
	if err != nil {
		return nil, err
	}
	attrs := parseAttrs(parts[1:])
	if !attrs.IsEmpty() {
		filtered := make([]*router.Domain, 0, len(domains))
		for _, domain := range domains {
			if attrs.Match(domain) {
				filtered = append(filtered, domain)
			}
		}
		domains = filtered
	}
	var matcher router.DomainMatcher
	if s.options.Matcher == "mph" || s.options.Matcher == "hybrid" {
		matcher, err = router.NewMphMatcherGroup(domains)
	} else {
		matcher, err = router.NewSuccinctMatcherGroup(domains)
	}
	if err != nil {
		return nil, err
	}
	if not {
		matcher = router.NewNotDomainMatcherGroup(matcher)
	}
	s.sites[country] = matcher
	return matcher, nil
}

func (s *Scope) LoadGeoIPMatcher(country string) (router.IPMatcher, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if matcher, ok := s.ips[country]; ok {
		return matcher, nil
	}
	key := strings.ToLower(country)
	not := strings.HasPrefix(key, "!")
	key = strings.TrimPrefix(key, "!")
	if key == "" {
		return nil, fmt.Errorf("empty geoip country")
	}
	path, err := s.resolve("GeoIP.dat")
	if err != nil {
		return nil, err
	}
	loader, err := s.loader()
	if err != nil {
		return nil, err
	}
	entries, err := loader.LoadIPByPath(path, key)
	if err != nil {
		return nil, err
	}
	matcher, err := router.NewGeoIPMatcher(entries)
	if err != nil {
		return nil, err
	}
	if not {
		matcher = router.NewNotIpMatcherGroup(matcher)
	}
	s.ips[country] = matcher
	return matcher, nil
}

func (s *Scope) loadDatabase(name string) (*maxminddb.Reader, error) {
	path, err := s.resolve(name)
	if err != nil {
		return nil, err
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return maxminddb.FromBytes(buf)
}

func (s *Scope) InitGeoIP() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.options.Mode || s.ipReader != nil {
		return nil
	}
	reader, err := s.loadDatabase("Country.mmdb")
	if err != nil {
		return err
	}
	value := mmdb.NewIPReader(reader)
	s.ipReader = &value
	return nil
}

func (s *Scope) InitASN() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.asnReader != nil {
		return nil
	}
	reader, err := s.loadDatabase("ASN.mmdb")
	if err != nil {
		return err
	}
	s.asnReader = &mmdb.ASNReader{Reader: reader}
	return nil
}

func (s *Scope) IPReader() mmdb.IPReader {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.ipReader
}

func (s *Scope) ASNReader() mmdb.ASNReader {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *s.asnReader
}

func (s *Scope) Refresh(name, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := NewScope(s.options)
	for key, value := range s.paths {
		next.paths[key] = value
	}
	next.paths[name] = path
	switch name {
	case "GeoSite.dat":
		for country := range s.sites {
			if _, err := next.LoadGeoSiteMatcher(country); err != nil {
				return err
			}
		}
		s.sites = next.sites
	case "GeoIP.dat":
		for country := range s.ips {
			if _, err := next.LoadGeoIPMatcher(country); err != nil {
				return err
			}
		}
		s.ips = next.ips
	case "Country.mmdb":
		if s.ipReader != nil {
			if err := next.InitGeoIP(); err != nil {
				return err
			}
			s.ipReader = next.ipReader
		}
	case "ASN.mmdb":
		if s.asnReader != nil {
			if err := next.InitASN(); err != nil {
				return err
			}
			s.asnReader = next.asnReader
		}
	default:
		return fmt.Errorf("unsupported scoped geodata resource %s", name)
	}
	s.paths[name] = path
	return nil
}
