package guardcore

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
)

type Config struct {
	CompilerTimeout        time.Duration
	MaxContentLength       int
	PreserveAttackPatterns bool
	MaxBodyInspectBytes    int
	SemanticThreshold      float64
	ThreatScoreThreshold   float64
}

func DefaultConfig() Config {
	return Config{
		CompilerTimeout:        2000 * time.Millisecond,
		MaxContentLength:       10000,
		PreserveAttackPatterns: true,
		MaxBodyInspectBytes:    262144,
		SemanticThreshold:      0.7,
		ThreatScoreThreshold:   1.0,
	}
}

func translatePattern(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); i++ {
		if i+1 < len(src) && src[i] == '\\' && src[i+1] == 'Z' && (i == 0 || src[i-1] != '\\') {
			b.WriteString(`\z`)
			i++
			continue
		}
		b.WriteByte(src[i])
	}
	return b.String()
}

func compileRE(src string, opts regexp2.RegexOptions, timeout time.Duration) (*regexp2.Regexp, error) {
	re, err := regexp2.Compile(translatePattern(src), opts)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		re.MatchTimeout = timeout
	}
	return re, nil
}

func compileREIgnoreCase(src string, timeout time.Duration) (*regexp2.Regexp, error) {
	return compileRE(src, regexp2.IgnoreCase, timeout)
}

type scanText struct {
	s   string
	rs  []rune
	b2r []int32
	n   int
}

func newScanText(s string) scanText {
	b2r := make([]int32, len(s)+1)
	rs := make([]rune, 0, len(s))
	r := 0
	for i := 0; i < len(s); {
		b2r[i] = int32(r)
		rn, sz := utf8.DecodeRuneInString(s[i:])
		rs = append(rs, rn)
		i += sz
		r++
	}
	b2r[len(s)] = int32(r)
	return scanText{s: s, rs: rs, b2r: b2r, n: r}
}

func (t scanText) runeOff(b int) int {
	if b >= len(t.s) {
		return t.n
	}
	return int(t.b2r[b])
}

func (t scanText) runes(start, end int) []rune {
	if start < 0 {
		start = 0
	}
	if end > t.n {
		end = t.n
	}
	if start >= end {
		return nil
	}
	return t.rs[start:end]
}

func (t scanText) str(start, end int) string {
	return string(t.runes(start, end))
}

type sMatch struct {
	t      scanText
	rStart int
	rEnd   int
	g1     string
}

func (m sMatch) text() string { return m.t.str(m.rStart, m.rEnd) }

func matchFromBytes(t scanText, bStart, bEnd int, g1 string) sMatch {
	return sMatch{t: t, rStart: t.runeOff(bStart), rEnd: t.runeOff(bEnd), g1: g1}
}

func findAllMatches(re *regexp2.Regexp, t scanText) ([]sMatch, bool) {
	var out []sMatch
	pos := 0
	n := len(t.s)
	for pos <= n {
		m, err := re.FindStringMatchStartingAt(t.s, pos)
		if err != nil {
			return nil, false
		}
		if m == nil {
			break
		}
		g1 := ""
		if g := m.GroupByNumber(1); g != nil && len(g.Captures) > 0 {
			g1 = g.String()
		}
		out = append(out, matchFromBytes(t, m.Index, m.Index+m.Length, g1))
		next := m.Index + m.Length
		if m.Length == 0 {
			next++
		}
		if next == pos {
			next++
		}
		pos = next
	}
	return out, true
}

func anchoredMatchAt(re *regexp2.Regexp, t scanText, start, ceiling int) (sMatch, bool) {
	if start >= ceiling {
		return sMatch{}, false
	}
	bStart := byteOffsetOfRune(t, start)
	bCeil := byteOffsetOfRune(t, ceiling)
	m, err := re.FindStringMatchStartingAt(t.s[:bCeil], bStart)
	if err != nil || m == nil || m.Index != bStart {
		return sMatch{}, false
	}
	return matchFromBytes(t, m.Index, m.Index+m.Length, ""), true
}

func byteOffsetOfRune(t scanText, r int) int {
	if r >= t.n {
		return len(t.s)
	}
	return byteOffsetViaSearch(t, r)
}

func byteOffsetViaSearch(t scanText, r int) int {
	lo, hi := 0, len(t.b2r)-1
	for lo < hi {
		mid := (lo + hi) / 2
		if int(t.b2r[mid]) < r {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}
