package guardcore

import (
	"net"
	"strings"
)

// DefaultExcludedHeaders mirrors the reference's _DEFAULT_EXCLUDED_HEADERS
// (guard_core/_utils/detection_config.py): the proxy identity, forwarding and
// browser-fingerprint headers that enter the detection scan through the
// excluded-header routing instead of the full category sweep. Entries are
// lowercase header names and always merged with
// SecurityConfig.ExcludedDetectionHeaders.
var DefaultExcludedHeaders = map[string]bool{
	"host":                     true,
	"user-agent":               true,
	"accept":                   true,
	"accept-encoding":          true,
	"connection":               true,
	"origin":                   true,
	"referer":                  true,
	"sec-fetch-site":           true,
	"sec-fetch-mode":           true,
	"sec-fetch-dest":           true,
	"sec-ch-ua":                true,
	"sec-ch-ua-mobile":         true,
	"sec-ch-ua-platform":       true,
	"forwarded":                true,
	"x-forwarded-for":          true,
	"x-forwarded-host":         true,
	"x-forwarded-proto":        true,
	"x-real-ip":                true,
	"x-client-ip":              true,
	"x-cluster-client-ip":      true,
	"cf-connecting-ip":         true,
	"true-client-ip":           true,
	"fly-client-ip":            true,
	"x-envoy-external-address": true,
}

// addressHeaderSkipCategories mirrors _HEADER_CATEGORY_EXCLUSIONS: excluded
// headers whose typical values are client addresses are known to false-positive
// the ssrf category, so an excluded match on them skips ssrf only; every other
// detection category still scans them.
var addressHeaderSkipCategories = map[string]bool{
	"host":                     true,
	"origin":                   true,
	"x-forwarded-for":          true,
	"x-forwarded-host":         true,
	"x-real-ip":                true,
	"x-client-ip":              true,
	"x-cluster-client-ip":      true,
	"cf-connecting-ip":         true,
	"true-client-ip":           true,
	"fly-client-ip":            true,
	"x-envoy-external-address": true,
	"via":                      true,
}

// ssrfSkipCategories is the single skip set both exclusion shapes resolve to.
var ssrfSkipCategories = map[string]bool{"ssrf": true}

// stripForwardedEntryPort is the port of
// guard_core._utils.ip_extraction._strip_forwarded_entry_port: it removes the
// port from a Forwarded/X-Forwarded-For list entry so the address itself can be
// parsed ("1.2.3.4:8080" -> "1.2.3.4", "[::1]:8080" -> "::1").
func stripForwardedEntryPort(value string) string {
	if strings.HasPrefix(value, "[") {
		closing := strings.Index(value, "]")
		if closing == -1 {
			return value
		}
		remainder := value[closing+1:]
		if remainder != "" && !(strings.HasPrefix(remainder, ":") && isASCIIdigits(remainder[1:])) {
			return value
		}
		return value[1:closing]
	}
	if strings.Count(value, ":") == 1 {
		host, port, found := strings.Cut(value, ":")
		if found && isASCIIdigits(port) {
			return host
		}
	}
	return value
}

func isASCIIdigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// valueLooksLikeAddressChain mirrors
// guard_core._utils.detection_config._value_looks_like_address_chain: every
// comma-separated token parses as an IP address once its port entry is
// stripped, so a value like "10.0.0.5, 172.16.0.1" reads as a proxy chain and
// not as an attack payload.
func valueLooksLikeAddressChain(value string) bool {
	tokens := make([]string, 0, 4)
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token != "" {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return false
	}
	for _, token := range tokens {
		if net.ParseIP(stripForwardedEntryPort(token)) == nil {
			return false
		}
	}
	return true
}

// excludedHeaderSkipCategories mirrors
// guard_core._utils.detection_config._excluded_header_skip_categories: for an
// excluded header it returns the categories the scan must suppress for that
// value. Address-carrying proxy headers skip ssrf for any value; any other
// excluded header skips ssrf only when its whole value parses as an address
// chain (so an XSS or SQLi payload in the same header still detects). A nil
// result means the header scans with every enabled category.
func excludedHeaderSkipCategories(name, value string) map[string]bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if addressHeaderSkipCategories[normalized] {
		return ssrfSkipCategories
	}
	if valueLooksLikeAddressChain(value) {
		return ssrfSkipCategories
	}
	return nil
}

// mergedExcludedDetectionHeaders resolves the exclusion set the header scan
// routes through: the hardcoded default set merged with the configured
// ExcludedDetectionHeaders (the reference's
// _resolve_excluded_headers without the route layer this port does not have).
func mergedExcludedDetectionHeaders(cfg *SecurityConfig) map[string]bool {
	merged := make(map[string]bool, len(DefaultExcludedHeaders)+len(cfg.ExcludedDetectionHeaders))
	for name := range DefaultExcludedHeaders {
		merged[name] = true
	}
	for name := range cfg.ExcludedDetectionHeaders {
		merged[strings.ToLower(name)] = true
	}
	return merged
}
