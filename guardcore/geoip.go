package guardcore

import (
	"log"
	"net"
	"os"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// GeoIP country resolution, ported from the reference IPInfoManager
// (guard_core/handlers/ipinfo_handler.py) and the GeoIPHandler protocol
// (guard_core/protocols/geo_ip_protocol.py). The country verdict itself
// lives in the ip_security check (pipeline.go), mirroring the reference
// _resolve_country_verdict / check_country_access in
// guard_core/_utils/access_control.py and guard_core/core/checks/helpers.py.

// CountryResolver mirrors the lookup half of the reference GeoIPHandler
// protocol: GetCountry returns the ISO country code for ip, or ok=false when
// the IP can not be resolved. Like the reference get_country it must be
// cheap, run inline per request, and report a miss instead of raising.
type CountryResolver interface {
	GetCountry(ip string) (string, bool)
}

// GeoIPManager is the built-in CountryResolver: a lazily opened MMDB reader
// over GeoIPDBPath, standing in for the reference IPInfoManager minus the
// download lifecycle (the Go engine reads a locally provisioned database
// instead of fetching country_asn.mmdb with an IPInfo token). A missing or
// corrupted database is a soft failure: every lookup reports a miss, exactly
// like the reference reader returning None after a failed initialization.
type GeoIPManager struct {
	DBPath string

	initOnce sync.Once
	mu       sync.RWMutex
	reader   *maxminddb.Reader
	failed   bool
}

// NewGeoIPManager returns a resolver over the MMDB file at dbPath. The file
// is opened on the first lookup, not here.
func NewGeoIPManager(dbPath string) *GeoIPManager {
	return &GeoIPManager{DBPath: dbPath}
}

// mmdbRecord mirrors the record shape the reference get_country reads: a
// top-level "country" string (the ipinfo country_asn.mmdb layout). A
// GeoLite2-style nested country.iso_code decodes to an empty string here and
// resolves as a miss, like the reference reading a top-level key.
type mmdbRecord struct {
	Country string `maxminddb:"country"`
}

// ensureLoaded opens the database once. A corrupted database is removed and
// reported like the reference _open_database_or_none; a missing database
// only means lookups miss.
func (m *GeoIPManager) ensureLoaded() {
	m.initOnce.Do(func() {
		reader, err := maxminddb.Open(m.DBPath)
		if err != nil {
			if removeErr := os.Remove(m.DBPath); removeErr == nil {
				log.Printf("IPInfo database at %s is corrupted, removing: %v", m.DBPath, err)
			} else {
				log.Printf("IPInfo database at %s is unavailable: %v", m.DBPath, err)
			}
			m.mu.Lock()
			m.failed = true
			m.mu.Unlock()
			return
		}
		m.mu.Lock()
		m.reader = reader
		m.mu.Unlock()
	})
}

// GetCountry resolves ip to its ISO country code, mirroring the reference
// get_country: an unavailable reader warns and misses, an unparseable IP or
// a failing lookup misses instead of raising.
func (m *GeoIPManager) GetCountry(ip string) (string, bool) {
	m.ensureLoaded()
	m.mu.RLock()
	reader, failed := m.reader, m.failed
	m.mu.RUnlock()
	if reader == nil {
		if failed {
			log.Printf("Geo-IP reader unavailable after a failed initialization attempt; returning no country for %s. Check the IPInfo token and network reachability, then call refresh() to retry.", ip)
		} else {
			log.Printf("Geo-IP reader uninitialized; returning no country for %s", ip)
		}
		return "", false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	var record mmdbRecord
	if err := reader.Lookup(parsed, &record); err != nil {
		log.Printf("Geographic lookup failed for %s: %v", ip, err)
		return "", false
	}
	if record.Country == "" {
		return "", false
	}
	return record.Country, true
}

// Close releases the database handle, mirroring IPInfoManager.close.
func (m *GeoIPManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.reader == nil {
		return nil
	}
	err := m.reader.Close()
	m.reader = nil
	return err
}
