package guardcore

import (
	"strings"
	"unicode/utf8"
)

const maxURLDecodeRounds = 4

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
}

func hexValue(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return c - 'a' + 10
	}
}

func decodePercentRuns(value string) (string, bool) {
	var b strings.Builder
	i := 0
	for i < len(value) {
		if value[i] != '%' || i+2 >= len(value) || !isHexDigit(value[i+1]) || !isHexDigit(value[i+2]) {
			b.WriteByte(value[i])
			i++
			continue
		}
		j := i
		for j+2 < len(value) && value[j] == '%' && isHexDigit(value[j+1]) && isHexDigit(value[j+2]) {
			j += 3
		}
		raw := make([]byte, 0, (j-i)/3)
		for k := i; k < j; k += 3 {
			raw = append(raw, hexValue(value[k+1])<<4|hexValue(value[k+2]))
		}
		if !utf8.Valid(raw) {
			return "", false
		}
		b.Write(raw)
		i = j
	}
	return b.String(), true
}

func foldDotSegmentParams(segment string) string {
	base, _, _ := strings.Cut(segment, ";")
	if base == "." || base == ".." {
		return base
	}
	return segment
}

func collapseDotSegments(decoded string) string {
	decoded = strings.ReplaceAll(decoded, "\\", "/")
	segments := make([]string, 0, strings.Count(decoded, "/")+1)
	for _, raw := range strings.Split(decoded, "/") {
		segment := foldDotSegmentParams(raw)
		if segment == "" || segment == "." {
			continue
		}
		if segment == ".." {
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
			continue
		}
		segments = append(segments, segment)
	}
	return "/" + strings.Join(segments, "/")
}

func normalizeURLPath(rawPath string) (string, bool) {
	decoded := rawPath
	for i := 0; i < maxURLDecodeRounds; i++ {
		next, ok := decodePercentRuns(decoded)
		if !ok {
			return "", false
		}
		decoded = next
	}
	if hasPercentRun(decoded) {
		return "", false
	}
	return collapseDotSegments(decoded), true
}

func hasPercentRun(value string) bool {
	for i := 0; i+2 < len(value); i++ {
		if value[i] == '%' && isHexDigit(value[i+1]) && isHexDigit(value[i+2]) {
			return true
		}
	}
	return false
}

func isSubtreeOrEqual(path, excluded string) bool {
	if excluded == "/" {
		return true
	}
	return path == excluded || strings.HasPrefix(path, excluded+"/")
}

func pathMatchesExclusions(normalizedPath string, normalizedExclusions []string) bool {
	for _, excluded := range normalizedExclusions {
		if isSubtreeOrEqual(normalizedPath, excluded) {
			return true
		}
	}
	return false
}
