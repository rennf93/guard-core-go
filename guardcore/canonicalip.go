package guardcore

import (
	"net/netip"
	"strings"
)

func stripIPBrackets(value string) string {
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return value[1 : len(value)-1]
	}
	return value
}

func CanonicalizeIP(value string) string {
	addr, err := netip.ParseAddr(stripIPBrackets(value))
	if err != nil {
		return value
	}
	return canonicalIPText(addr)
}

func canonicalIPText(addr netip.Addr) string {
	if addr.Is4In6() {
		if addr.Zone() == "" {
			return addr.Unmap().String()
		}
		return "::ffff:" + addr.Unmap().String() + "%" + addr.Zone()
	}
	return addr.String()
}
