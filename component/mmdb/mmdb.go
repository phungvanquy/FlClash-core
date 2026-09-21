package mmdb

import (
	"sync"

	mihomoOnce "github.com/metacubex/mihomo/common/once"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

var (
	ipReader  IPReader
	asnReader ASNReader
	ipOnce    sync.Once
	asnOnce   sync.Once
)

func NewIPReader(reader *maxminddb.Reader) IPReader {
	result := IPReader{Reader: reader}
	switch reader.Metadata.DatabaseType {
	case "sing-geoip":
		result.databaseType = typeSing
	case "Meta-geoip0":
		result.databaseType = typeMetaV0
	default:
		result.databaseType = typeMaxmind
	}
	return result
}

func LoadFromBytes(buffer []byte) {
	ipOnce.Do(func() {
		mmdb, err := maxminddb.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})
}

func Verify(path string) bool {
	instance, err := maxminddb.Open(path)
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func IPInstance() IPReader {
	ipOnce.Do(func() {
		mmdbPath := C.Path.MMDB()
		log.Infoln("Load MMDB file: %s", mmdbPath)
		mmdb, err := maxminddb.Open(mmdbPath)
		if err != nil {
			log.Fatalln("Can't load MMDB: %s", err.Error())
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})

	return ipReader
}

func ASNInstance() ASNReader {
	asnOnce.Do(func() {
		ASNPath := C.Path.ASN()
		log.Infoln("Load ASN file: %s", ASNPath)
		asn, err := maxminddb.Open(ASNPath)
		if err != nil {
			log.Fatalln("Can't load ASN: %s", err.Error())
		}
		asnReader = ASNReader{Reader: asn}
	})

	return asnReader
}

func ReloadIP() {
	mihomoOnce.Reset(&ipOnce)
}

func ReloadASN() {
	mihomoOnce.Reset(&asnOnce)
}

func CloseLoadedIP() {
	if ipReader.Reader != nil {
		_ = ipReader.Reader.Close()
	}
}

func CloseLoadedASN() {
	if asnReader.Reader != nil {
		_ = asnReader.Reader.Close()
	}
}
