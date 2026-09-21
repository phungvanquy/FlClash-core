package common

import (
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type ASN struct {
	Base
	asn         string
	adapter     string
	noResolveIP bool
	isSourceIP  bool
	scope       *geodata.Scope
}

func (a *ASN) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if !a.noResolveIP && !a.isSourceIP && helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if a.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}

	var reader mmdb.ASNReader
	if a.scope != nil {
		reader = a.scope.ASNReader()
	} else {
		reader = mmdb.ASNInstance()
	}
	asn, aso := reader.LookupASN(ip.AsSlice())
	if a.isSourceIP {
		metadata.SrcIPASN = asn + " " + aso
	} else {
		metadata.DstIPASN = asn + " " + aso
	}

	return a.asn == asn, a.adapter
}

func (a *ASN) RuleType() C.RuleType {
	if a.isSourceIP {
		return C.SrcIPASN
	}
	return C.IPASN
}

func (a *ASN) Adapter() string {
	return a.adapter
}

func (a *ASN) Payload() string {
	return a.asn
}

func (a *ASN) GetASN() string {
	return a.asn
}

func NewIPASN(asn string, adapter string, isSrc, noResolveIP bool) (*ASN, error) {
	if err := geodata.InitASN(); err != nil {
		log.Errorln("can't initial ASN: %s", err)
		return nil, err
	}

	return &ASN{
		Base:        Base{},
		asn:         asn,
		adapter:     adapter,
		noResolveIP: noResolveIP,
		isSourceIP:  isSrc,
	}, nil
}

var _ C.Rule = (*ASN)(nil)

func NewScopedIPASN(asn, adapter string, isSrc, noResolveIP bool, scope *geodata.Scope) (*ASN, error) {
	if scope == nil {
		return NewIPASN(asn, adapter, isSrc, noResolveIP)
	}
	if err := scope.InitASN(); err != nil {
		return nil, err
	}
	return &ASN{asn: asn, adapter: adapter, isSourceIP: isSrc, noResolveIP: noResolveIP, scope: scope}, nil
}
