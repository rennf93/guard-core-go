package guardcore

import (
	"sort"
	"unicode"

	"github.com/dlclark/regexp2"
)

var cmdNewlineShellDashCCompiled = mustCompileI(cmdNewlineShellDashCSource)

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isSpaceRune(r rune) bool {
	return unicode.IsSpace(r)
}

func cmdInjectionShellDashCFinditer(t scanText) []rmatch {
	var out []rmatch
	lastEnd := 0
	rs := t.rs
	i := 0
	for i <= t.n {
		nl := indexOfRune(rs, '\n', i)
		if nl == -1 {
			break
		}
		start := nl
		pos := nl + 1
		for pos < t.n && rs[pos] != '\r' && rs[pos] != '\n' && isSpaceRune(rs[pos]) {
			pos++
		}
		for {
			j := pos
			k := j
			for k < t.n && rs[k] != '=' && rs[k] != ';' && rs[k] != '|' && rs[k] != '&' && !isSpaceRune(rs[k]) {
				k++
			}
			if k == j || k >= t.n || rs[k] != '=' {
				break
			}
			m := k + 1
			for m < t.n && rs[m] != ';' && rs[m] != '|' && rs[m] != '&' && !isSpaceRune(rs[m]) {
				m++
			}
			if m == k+1 {
				break
			}
			s := m
			for s < t.n && isSpaceRune(rs[s]) {
				s++
			}
			if s == m {
				break
			}
			pos = s
		}
		if start >= lastEnd {
			if m, ok := findFirstAt(cmdNewlineShellDashCCompiled, t, start, t.n+1); ok {
				out = append(out, m)
				lastEnd = m.end()
			} else {
				lastEnd = pos
			}
		} else {
			lastEnd = pos
		}
		i = nl + 1
	}
	return out
}

var loadFilePrefix = mustCompile(`LOAD_FILE\s*\(`, regexp2.IgnoreCase, windowTimeout)
var loadFileTerm = mustCompile(`\)`, 0, windowTimeout)

func loadFileScanMatches(t scanText) []rmatch {
	return boundedFinditer(mustCompileI(sqliLoadFileSource), t, scanBound{prefix: loadFilePrefix, term: loadFileTerm})
}

var cmdDollarParenPrefix = mustCompile(`[;&|]\s*\$\(`, 0, windowTimeout)
var cmdDollarParenTerm = mustCompile(`\)`, 0, windowTimeout)
var cmdDollarBracePrefix = mustCompile(`[;&|]\s*\$\{`, 0, windowTimeout)
var cmdDollarBraceTerm = mustCompile(`\}`, 0, windowTimeout)

func cmdInjectionDollarScanMatches(t scanText) []rmatch {
	re := mustCompileI(cmdDollarSubstSource)
	out := boundedFinditer(re, t, scanBound{prefix: cmdDollarParenPrefix, term: cmdDollarParenTerm})
	out = append(out, boundedFinditer(re, t, scanBound{prefix: cmdDollarBracePrefix, term: cmdDollarBraceTerm})...)
	return out
}

var globWildcardAtomCompiled = mustCompileI(globWildcardAtomSource)

func isGlobRunRune(r rune) bool {
	return isWordRune(r) || containsRune("./*?-", r)
}

func globWildcardScanMatches(t scanText) []rmatch {
	var matches []rmatch
	rs := t.rs
	i := 0
	for i < t.n {
		if !isGlobRunRune(rs[i]) {
			i++
			continue
		}
		j := i
		for j < t.n && isGlobRunRune(rs[j]) {
			j++
		}
		hasWildcard := false
		for k := i; k < j; k++ {
			if rs[k] == '?' || rs[k] == '*' {
				hasWildcard = true
				break
			}
		}
		if hasWildcard {
			if m, ok := findFirstAt(globWildcardAtomCompiled, t, i, j); ok {
				matches = append(matches, m)
			}
		}
		i = j
	}
	return matches
}

var ldapNullByteTailRE = mustCompile(`\*\)+(?:%00|\\u0000|\\x00|\\0|\x00)`, 0, windowTimeout)
var ldapNullByteDecodedTailRE = mustCompile(`\*\)+\x00`, 0, windowTimeout)
var ldapNullByteAttrCompiled = mustCompileI(ldapNullByteAttrSource)
var ldapNullByteDecodedAttrCompiled = mustCompileI(ldapNullByteDecodedAttrSource)

func ldapNullByteAttrNameStart(t scanText, equalsPos int) (int, bool) {
	i := equalsPos
	for i > 0 && (isWordRune(t.rs[i-1]) || t.rs[i-1] == '-') {
		i--
	}
	if i == equalsPos || !unicode.IsLetter(t.rs[i]) {
		return 0, false
	}
	return i, true
}

func ldapNullByteValueStart(t scanText, starPos int) int {
	i := starPos
	for i > 0 && (isWordRune(t.rs[i-1]) || isSpaceRune(t.rs[i-1])) {
		i--
	}
	return i
}

func ldapNullByteAttrFinditer(t scanText, compiled *regexp2P, tail *regexp2P) []rmatch {
	if indexOfRune(t.rs, '*', 0) == -1 || indexOfRune(t.rs, ')', 0) == -1 {
		return nil
	}
	var out []rmatch
	lastEnd := 0
	for _, tailMatch := range findAllMatches(tail, t) {
		starPos := tailMatch.start()
		if starPos < lastEnd {
			continue
		}
		valueStart := ldapNullByteValueStart(t, starPos)
		if valueStart == 0 || t.rs[valueStart-1] != '=' {
			continue
		}
		nameStart, ok := ldapNullByteAttrNameStart(t, valueStart-1)
		if !ok {
			continue
		}
		if m, ok := findFirstAt(compiled, t, nameStart, tailMatch.end()); ok {
			out = append(out, m)
			lastEnd = m.end()
		}
	}
	return out
}

var quoteSpliceCompiled = mustCompileI(quoteSpliceCandidateSource)

func quoteSpliceFinditer(t scanText) []rmatch {
	var out []rmatch
	lastEnd := 0
	n := t.n
	rs := t.rs
	i := 0
	for i < n {
		if rs[i] != '\'' && rs[i] != '"' {
			i++
			continue
		}
		qStart := i
		for i < n && (rs[i] == '\'' || rs[i] == '"') {
			i++
		}
		qEnd := i
		if qStart < lastEnd {
			continue
		}
		if qEnd >= n || !isWordRune(rs[qEnd]) {
			continue
		}
		w := qStart
		for w > 0 && isWordRune(rs[w-1]) {
			w--
		}
		if w == qStart {
			continue
		}
		if m, ok := findFirstAt(quoteSpliceCompiled, t, w, t.n+1); ok {
			out = append(out, m)
			lastEnd = m.end()
		} else {
			lastEnd = qEnd
		}
	}
	return out
}

var pickleGlobalCompiled = mustCompileI(pickleGlobalGenericSource)

const pickleIdentMaxLen = 101
const pickleDottedSegmentsMax = 20

func pickleFirstValidMarker(t scanText, floor, ceiling int) (int, bool) {
	start := floor
	for {
		best := -1
		for _, target := range []rune{'c', 'C'} {
			pos := indexOfRune(t.rs, target, start)
			if pos != -1 && pos < ceiling && (best == -1 || pos < best) {
				best = pos
			}
		}
		if best == -1 {
			return 0, false
		}
		if best+1 < t.n && unicode.IsLetter(t.rs[best+1]) {
			return best, true
		}
		start = best + 1
	}
}

func pickleChainStart(t scanText, nl1, floor int) (int, bool) {
	segEnd := nl1
	earliest := -1
	for i := 0; i < pickleDottedSegmentsMax+1; i++ {
		dotPos := lastIndexOfRuneFrom(t.rs, '.', segEnd)
		if dotPos < floor {
			dotPos = -1
		}
		segStart := floor
		if dotPos >= floor {
			segStart = dotPos + 1
		}
		segFloor := segStart
		if alt := segEnd - pickleIdentMaxLen - 1; alt > segFloor {
			segFloor = alt
		}
		if cPos, ok := pickleFirstValidMarker(t, segFloor, segEnd); ok {
			earliest = cPos
		}
		if dotPos < floor {
			break
		}
		if !pickleIdentIsFull(t.str(segStart, segEnd)) {
			break
		}
		segEnd = dotPos
	}
	if earliest == -1 {
		return 0, false
	}
	return earliest, true
}

func pickleIdentIsFull(s string) bool {
	if len(s) == 0 || len(s) > 101 {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func pickleGlobalGenericFinditer(t scanText) []rmatch {
	var newlinePositions []int
	for i, r := range t.rs {
		if r == '\n' {
			newlinePositions = append(newlinePositions, i)
		}
	}
	if len(newlinePositions) < 2 {
		return nil
	}
	var nonModulePositions []int
	for i, r := range t.rs {
		if !isWordRune(r) && r != '.' {
			nonModulePositions = append(nonModulePositions, i)
		}
	}
	var out []rmatch
	lastEnd := 0
	for idx := 0; idx+1 < len(newlinePositions); idx++ {
		nl1, nl2 := newlinePositions[idx], newlinePositions[idx+1]
		if nl1 < lastEnd {
			continue
		}
		if !pickleIdentIsFull(t.str(nl1+1, nl2)) {
			continue
		}
		runStart := floorMax(lastEnd)
		pos := sort.SearchInts(nonModulePositions, nl1)
		if pos > 0 {
			if alt := nonModulePositions[pos-1] + 1; alt > runStart {
				runStart = alt
			}
		}
		start, ok := pickleChainStart(t, nl1, runStart)
		if !ok {
			continue
		}
		if m, ok2 := findFirstAt(pickleGlobalCompiled, t, start, t.n+1); ok2 {
			out = append(out, m)
			lastEnd = m.end()
		}
	}
	return out
}

func floorMax(f int) int {
	if f < 0 {
		return 0
	}
	return f
}

// The three finders below mirror the Python engine's plain regex scans for
// sources that regexp2 catastrophically backtracks on (binary-noise bodies hit
// the 2s MatchTimeout and produced pattern_timeout threats where Python's re
// module completes in milliseconds). Each finder reproduces the regex match
// semantics exactly, with linear scans instead of backtracking.

// gluedBacktickCandidateFinditer mirrors
// (?<!`)`(?:[A-Za-z0-9_./~]|\$[({])(?:[^`\\\n]|\\.)*`
func gluedBacktickCandidateFinditer(t scanText) []rmatch {
	var out []rmatch
	rs := t.rs
	i := 0
	for i < t.n {
		if rs[i] != '`' || (i > 0 && rs[i-1] == '`') {
			i++
			continue
		}
		end, ok := scanBacktickCandidateBody(rs, i)
		if !ok {
			i++
			continue
		}
		out = append(out, matchFromIndices(t, i, end, ""))
		i = end
	}
	return out
}

func scanBacktickCandidateBody(rs []rune, open int) (int, bool) {
	n := len(rs)
	j := open + 1
	if j >= n {
		return 0, false
	}
	c := rs[j]
	if isWordRune(c) || c == '.' || c == '/' || c == '~' {
		j++
	} else if c == '$' && j+1 < n && (rs[j+1] == '(' || rs[j+1] == '{') {
		j += 2
	} else {
		return 0, false
	}
	for j < n {
		c := rs[j]
		if c == '`' {
			return j + 1, true
		}
		if c == '\n' {
			return 0, false
		}
		if c == '\\' {
			if j+1 < n && rs[j+1] != '\n' {
				j += 2
				continue
			}
			return 0, false
		}
		j++
	}
	return 0, false
}

// gluedDollarSubstitutionCandidateFinditer mirrors
// \$\((?:[^()\\\n]|\\.)*\)|\$\{(?:[^{}\\\n]|\\.)*\}
func gluedDollarSubstitutionCandidateFinditer(t scanText) []rmatch {
	var out []rmatch
	rs := t.rs
	i := 0
	for i < t.n {
		if rs[i] != '$' || i+1 >= t.n {
			i++
			continue
		}
		var closeRune, twin rune
		switch rs[i+1] {
		case '(':
			closeRune, twin = ')', '('
		case '{':
			closeRune, twin = '}', '{'
		default:
			i++
			continue
		}
		end, ok := scanDollarSubstitutionBody(rs, i+2, closeRune, twin)
		if !ok {
			i++
			continue
		}
		out = append(out, matchFromIndices(t, i, end, ""))
		i = end
	}
	return out
}

func scanDollarSubstitutionBody(rs []rune, j int, closeRune, twin rune) (int, bool) {
	n := len(rs)
	for j < n {
		c := rs[j]
		if c == closeRune {
			return j + 1, true
		}
		if c == '\n' || c == twin {
			return 0, false
		}
		if c == '\\' {
			if j+1 < n && rs[j+1] != '\n' {
				j += 2
				continue
			}
			return 0, false
		}
		j++
	}
	return 0, false
}

// ldapParenConjunctionFinditer mirrors \(\s*[&|]\s*
func ldapParenConjunctionFinditer(t scanText) []rmatch {
	var out []rmatch
	rs := t.rs
	i := 0
	for i < t.n {
		if rs[i] != '(' {
			i++
			continue
		}
		j := i + 1
		for j < t.n && isSpaceRune(rs[j]) {
			j++
		}
		if j >= t.n || (rs[j] != '&' && rs[j] != '|') {
			i++
			continue
		}
		j++
		for j < t.n && isSpaceRune(rs[j]) {
			j++
		}
		out = append(out, matchFromIndices(t, i, j, ""))
		i = j
	}
	return out
}
