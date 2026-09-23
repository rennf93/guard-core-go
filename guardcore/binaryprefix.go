package guardcore

// Binary noise gate (guard-core 4.0.3 parity, upstream commit 436d6f72).
//
// Random binary content (zip uploads, multipart file parts) decodes to text
// dense in "artifact" characters and reliably trips a small frozen registry of
// low-specificity shell-source heuristics, blocking and auto-banning real
// binary uploads. Matches from those noise-prone patterns, and only those, are
// discarded when the window of 64 characters on each side of the match holds
// 4 or more artifact characters. Signature patterns are never gated.
//
// String model: the Python engine scans surrogateescape-decoded text and its
// artifact classes are evaluated over decoded code points, including the
// surrogateescape range U+DC80-U+DCFF. This port scans rune slices: every
// scanned string is a Go string whose invalid UTF-8 bytes were already mapped
// to U+FFFD when the raw body bytes were converted to text (rune conversion).
// U+FFFD is part of the Python artifact class, so artifact density on real
// binary bytes matches Python; the U+DC80-U+DCFF class cannot occur in a Go
// string and needs no separate arm here. All other classes are compared as
// runes (code points), mirroring Python's code point indices, and match
// positions are rune indices from scanText, which is the same coordinate
// system Python uses for re.Match spans.

const binaryDensityRadius = 64
const binaryDensityLimit = 4

// binaryNoiseGateEnabled allows tests to disable the gate (the Python honesty
// test monkeypatches match_is_binary_dense to always False to prove the frozen
// registry is truthful: every registered pattern really does fire on random
// binary noise when the gate is off).
var binaryNoiseGateEnabled = true

// isBinaryArtifactRune mirrors _BINARY_ARTIFACT_RE from
// guard_core/detection_engine/binary_prefix.py: control characters other than
// tab, newline and carriage return, DEL, the Latin-1/Latin-Ext-A artifact
// bytes outside the small text allowlist, and the Unicode replacement
// character.
func isBinaryArtifactRune(r rune) bool {
	switch {
	case r >= 0x00 && r <= 0x08:
		return true
	case r == 0x0b || r == 0x0c:
		return true
	case r >= 0x0e && r <= 0x1f:
		return true
	case r == 0x7f:
		return true
	case r >= 0x80 && r <= 0xa2:
		return true
	case r == 0xa4:
		return true
	case r >= 0xa6 && r <= 0xa9:
		return true
	case r >= 0xab && r <= 0xaf:
		return true
	case r == 0xb4:
		return true
	case r >= 0xb6 && r <= 0xb8:
		return true
	case r >= 0xbb && r <= 0xbf:
		return true
	case r >= 0x0180 && r <= 0x024f:
		return true
	case r == 0xfffd:
		return true
	}
	return false
}

// binaryPrefix is an O(1)-per-query prefix-sum of artifact rune counts over a
// scanned scanText: prefix[i] counts artifact runes in t.rs[:i].
type binaryPrefix []int32

// buildBinaryPrefix is O(n) over the scanned string and runs once per scanned
// string (per detection view), not once per match.
func buildBinaryPrefix(t scanText) binaryPrefix {
	prefix := make(binaryPrefix, t.n+1)
	count := int32(0)
	for i, r := range t.rs {
		if isBinaryArtifactRune(r) {
			count++
		}
		prefix[i+1] = count
	}
	return prefix
}

// matchIsBinaryDense reports whether the artifact count in the window of
// binaryDensityRadius runes on each side of the [start, end) match reaches
// binaryDensityLimit. A nil prefix disables the gate (parity with the Python
// binary_prefix=None path).
func (bp binaryPrefix) matchIsBinaryDense(start, end int) bool {
	if bp == nil {
		return false
	}
	high := end + binaryDensityRadius
	if high > len(bp)-1 {
		high = len(bp) - 1
	}
	low := start - binaryDensityRadius
	if low < 0 {
		low = 0
	}
	return bp[high]-bp[low] >= binaryDensityLimit
}

// shellKeywordCommandSource is the low-specificity shell keyword heuristic
// from the Python pattern table (_SHELL_KEYWORD_COMMAND_RE).
const shellKeywordCommandSource = "[;|&]\\s*(?:ls|cat|rm|id|whoami|uname|wget|curl|nc|netcat|socat|bash|sh|python|perl)\\b"

// noisePronePatternSources is the frozen registry of low-specificity
// shell-source heuristics (backtick pairs, dollar substitutions, quote splice,
// glob wildcards, template fragments, plus the SSTI hash-brace shape and LDAP
// paren conjunction shapes that share the same noise profile). It is keyed by
// pattern source, exactly like the Python NOISE_PRONE_PATTERN_SOURCES
// frozenset in guard_core/handlers/_suspatterns_pattern_table.py.
var noisePronePatternSources = map[string]bool{
	gluedBacktickCandidateSource:           true,
	gluedDollarSubstitutionCandidateSource: true,
	cmdDollarSubstSource:                   true,
	shellKeywordCommandSource:              true,
	quoteSpliceCandidateSource:             true,
	globWildcardAtomSource:                 true,
	templateDollarBraceCallSource:          true,
	sstiHashBraceShapeSource:               true,
	ldapParenConjunctionSource:             true,
	// SQLi comment terminators span arbitrary whitespace between the quote
	// and the -- / # terminator, so they routinely fire inside text-decoded
	// binary bodies (e.g. "'\n--" byte runs in compressed payloads).
	// Parity with upstream commit f5d53ca5.
	sqliCommentTerminatorSource: true,
}
