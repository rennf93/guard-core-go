package guardcore

import (
	"html"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

var hexEscapeRE = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
var unicodeEscapeRE = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
var percentUEscapeRE = regexp.MustCompile(`(?i)%u([0-9a-fA-F]{4})`)
var percentByteRunRE = regexp.MustCompile(`(?:%[0-9a-fA-F]{2})+`)
var ldapHexEscapeStdRE = regexp.MustCompile(`\\([0-9a-fA-F]{2})`)

type overlongLeadSpec struct {
	length  int
	mask    byte
	contMin byte
	contMax byte
}

var overlongLeadSpecs = map[byte]overlongLeadSpec{
	0xC0: {2, 0x1F, 0x80, 0xBF},
	0xC1: {2, 0x1F, 0x80, 0xBF},
	0xE0: {3, 0x0F, 0x80, 0x9F},
	0xF0: {4, 0x07, 0x80, 0x8F},
}

func decodeHexEscapes(content string) string {
	return hexEscapeRE.ReplaceAllStringFunc(content, func(m string) string {
		sub := hexEscapeRE.FindStringSubmatch(m)
		v, err := parseHex2(sub[1])
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

func parseHex2(s string) (int, error) {
	v := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, errBadHex
		}
		v = v*16 + d
	}
	return v, nil
}

var errBadHex = hexError{}

type hexError struct{}

func (hexError) Error() string { return "bad hex" }

func decodeUnicodeEscapes(content string) string {
	return unicodeEscapeRE.ReplaceAllStringFunc(content, func(m string) string {
		sub := unicodeEscapeRE.FindStringSubmatch(m)
		v, err := parseHex2(sub[1])
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

func decodePercentUEscapes(content string) string {
	return percentUEscapeRE.ReplaceAllStringFunc(content, func(m string) string {
		sub := percentUEscapeRE.FindStringSubmatch(m)
		v, err := parseHex2(sub[1])
		if err != nil {
			return m
		}
		return string(rune(v))
	})
}

func decodeOverlongSequenceAt(raw []byte, index int) (rune, int, bool) {
	spec, ok := overlongLeadSpecs[raw[index]]
	if !ok || index+spec.length > len(raw) {
		return 0, 0, false
	}
	continuations := raw[index+1 : index+spec.length]
	if continuations[0] < spec.contMin || continuations[0] > spec.contMax {
		return 0, 0, false
	}
	for _, b := range continuations[1:] {
		if b < 0x80 || b > 0xBF {
			return 0, 0, false
		}
	}
	codepoint := uint32(raw[index] & spec.mask)
	for _, b := range continuations {
		codepoint = (codepoint << 6) | uint32(b&0x3F)
	}
	return rune(codepoint), spec.length, true
}

func lenientOverlongUTF8Decode(raw []byte) string {
	var b strings.Builder
	index := 0
	for index < len(raw) {
		if ch, consumed, ok := decodeOverlongSequenceAt(raw, index); ok {
			b.WriteRune(ch)
			index += consumed
		} else if raw[index] < 0x80 {
			b.WriteByte(raw[index])
			index++
		} else {
			index++
		}
	}
	return b.String()
}

func decodeOverlongUTF8PercentRuns(content string) string {
	return percentByteRunRE.ReplaceAllStringFunc(content, func(m string) string {
		raw := make([]byte, 0, len(m)/3)
		for i := 0; i+2 < len(m); i += 3 {
			v, err := parseHex2(m[i+1 : i+3])
			if err != nil {
				return m
			}
			raw = append(raw, byte(v))
		}
		if utf8.Valid(raw) {
			return m
		}
		return lenientOverlongUTF8Decode(raw)
	})
}

func urlUnquote(content string) string {
	// Parity with Python's urllib.parse.unquote(content, errors="ignore"):
	// literal characters pass through untouched (they are never routed
	// through the byte decoder, so invalid bytes cannot be dropped from
	// between a '%' and later hex digits, which would fabricate new escape
	// sequences and keep the decode loop mutating). Only contiguous %xx
	// byte runs are percent-decoded and UTF-8 decoded with invalid bytes
	// ignored.
	var b strings.Builder
	i := 0
	for i < len(content) {
		c := content[i]
		if c != '%' {
			sz := utf8Len(content[i:])
			b.WriteString(content[i : i+sz])
			i += sz
			continue
		}
		var raw []byte
		for i+3 <= len(content) && content[i] == '%' {
			v, err := parseHex2(content[i+1 : i+3])
			if err != nil {
				break
			}
			raw = append(raw, byte(v))
			i += 3
		}
		if len(raw) > 0 {
			b.WriteString(decodeUTF8Ignore(raw))
		} else {
			b.WriteByte('%')
			i++
		}
	}
	return b.String()
}

func utf8Len(b string) int {
	_, sz := utf8.DecodeRuneInString(b)
	if sz == 0 {
		return 1
	}
	return sz
}

func decodeUTF8Ignore(raw []byte) string {
	var b strings.Builder
	i := 0
	for i < len(raw) {
		r, sz := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && sz == 1 {
			i++
			continue
		}
		b.WriteRune(r)
		i += sz
	}
	return b.String()
}

func htmlUnescape(content string) string {
	return html.UnescapeString(content)
}

func decodeLDAPHexEscapes(content string) string {
	// Go std regexp is byte-safe (Python parity: re.sub on str). The
	// regexp2 Match.Index is a rune index and must never be used to slice
	// the input by bytes; doing so split multi-byte characters into
	// invalid bytes, which recombined into new escape sequences and kept
	// the decode loop mutating on binary content.
	return ldapHexEscapeStdRE.ReplaceAllStringFunc(content, func(m string) string {
		sub := ldapHexEscapeStdRE.FindStringSubmatch(m)
		if v, err := parseHex2(sub[1]); err == nil {
			return string(rune(v))
		}
		return m
	})
}

var lookalikeMap = map[rune]string{
	0x2044: "/",
	0xFF0F: "/",
	0x29F8: "/",
	0x0130: "I",
	0x0131: "i",
	0x200B: "",
	0x200C: "",
	0x200D: "",
	0xFEFF: "",
	0x00AD: "",
	0x034F: "",
	0x180E: "",
	0x2028: "\n",
	0x2029: "\n",
	0xE000: "",
	0xFFF0: "",
	0x01C0: "|",
	0x037E: ";",
	0x2215: "/",
	0x2216: "\\",
	0xFF1C: "<",
	0xFF1E: ">",
	0xFF1B: ";",
	0xFF5C: "|",
	0xFF06: "&",
}

func normalizeUnicode(content string) string {
	normalized := nfkcString(content)
	if !strings.ContainsFunc(normalized, func(r rune) bool {
		_, ok := lookalikeMap[r]
		return ok
	}) {
		return normalized
	}
	var b strings.Builder
	for _, r := range normalized {
		if rep, ok := lookalikeMap[r]; ok {
			b.WriteString(rep)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func removeNullAndControlBytes(content string) string {
	var b strings.Builder
	for _, r := range content {
		if r == 0 {
			continue
		}
		if r < 0x20 && r != 9 && r != 10 && r != 13 {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func removeExcessiveWhitespace(content string) string {
	var b strings.Builder
	inSpace := false
	for _, r := range content {
		if unicode.IsSpace(r) {
			inSpace = true
			continue
		}
		if inSpace {
			b.WriteByte(' ')
			inSpace = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	trimmed := strings.TrimLeft(out, " ")
	trimmed = strings.TrimRight(trimmed, " ")
	return trimmed
}

func stripSQLComments(content string) string {
	re := regexp2.MustCompile(`(?<!\w)/\*(?!!)(.*?)\*/|/\*(?!!)(.*?)\*/(?!\w)`, regexp2.Singleline)
	// Runes API: Match.Index is a rune index; slicing the byte string with
	// rune offsets split multi-byte characters on binary content.
	rs := []rune(content)
	out := make([]rune, 0, len(rs))
	pos := 0
	for {
		m, err := re.FindRunesMatchStartingAt(rs, pos)
		if err != nil || m == nil {
			break
		}
		if m.Index < pos || m.Index+m.Length > len(rs) {
			// Defensive: keep the scan monotonic.
			pos++
			continue
		}
		body := m.GroupByNumber(1)
		if body == nil || len(body.Captures) == 0 {
			body = m.GroupByNumber(2)
		}
		out = append(out, rs[pos:m.Index]...)
		out = append(out, ' ')
		out = append(out, []rune(body.String())...)
		out = append(out, ' ')
		pos = m.Index + m.Length
	}
	out = append(out, rs[pos:]...)
	lineRE := regexp.MustCompile(`--|#`)
	return lineRE.ReplaceAllString(string(out), " ")
}
