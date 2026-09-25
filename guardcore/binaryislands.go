package guardcore

import "unicode/utf8"

// Binary islands (guard-core 4.0.4 parity, upstream commit 5f399234).
//
// A multipart file-part payload whose binary artifact characters fill at
// least a fifth of it is reduced to its printable runs before pattern
// scanning: compressed or encrypted upload bytes stop producing attack-shaped
// matches whose rate grows with file size, while text genuinely embedded in
// an upload (a script inside a PDF, a stored path inside an archive) forms
// printable runs past the minimum length and is still scanned in full.
//
// String model: like the binary noise gate (binaryprefix.go), artifact classes
// are evaluated over decoded code points. Invalid UTF-8 bytes of a Go string
// become U+FFFD during rune conversion; U+FFFD is part of the Python artifact
// class and is excluded from the printable-run class, so binary bytes break
// islands exactly like the surrogateescape range does in Python.

// binaryLikeArtifactRatio mirrors _BINARY_LIKE_ARTIFACT_RATIO from
// guard_core/detection_engine/binary_islands.py: a payload is binary-like
// when artifact characters make up at least a fifth of it.
const binaryLikeArtifactRatio = 0.2

// valueIsBinaryLike mirrors value_is_binary_like from
// guard_core/detection_engine/binary_islands.py: the artifact-character ratio
// of the content reaches binaryLikeArtifactRatio.
func valueIsBinaryLike(content string) bool {
	if content == "" {
		return false
	}
	total := 0
	artifacts := 0
	for _, r := range content {
		total++
		if isBinaryArtifactRune(r) {
			artifacts++
		}
	}
	return float64(artifacts)/float64(total) >= binaryLikeArtifactRatio
}

// printableIslandRune reports whether r belongs to the island run class
// _ISLAND_RUN_RE from guard_core/detection_engine/binary_islands.py:
// tab, newline, carriage return, printable ASCII, and the wide non-control
// Unicode ranges. The Unicode replacement character (and every other
// artifact) is excluded, so binary bytes end a run.
func printableIslandRune(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return true
	case r >= 0x20 && r <= 0x7e:
		return true
	case r >= 0xa1 && r <= 0xd7ff:
		return true
	case r >= 0xe000 && r <= 0xfffc:
		return true
	case r >= 0xfffe && r <= 0xffff:
		return true
	case r >= 0x10000 && r <= 0x10ffff:
		return true
	}
	return false
}

// extractBinaryIslands mirrors extract_binary_islands from
// guard_core/detection_engine/binary_islands.py: the maximal printable runs
// of the content whose rune length reaches minRunLength, in order. A minimum
// of 1 or below keeps the whole content (Python returns [content]).
func extractBinaryIslands(content string, minRunLength int) []string {
	if minRunLength <= 1 {
		return []string{content}
	}
	var islands []string
	runStart, runEnd := -1, 0
	runLen := 0
	for i, r := range content {
		if printableIslandRune(r) {
			if runStart < 0 {
				runStart = i
			}
			runEnd = i + utf8.RuneLen(r)
			runLen++
			continue
		}
		if runStart >= 0 && runLen >= minRunLength {
			islands = append(islands, content[runStart:runEnd])
		}
		runStart = -1
		runLen = 0
	}
	if runStart >= 0 && runLen >= minRunLength {
		islands = append(islands, content[runStart:runEnd])
	}
	return islands
}
