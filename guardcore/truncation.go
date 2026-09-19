package guardcore

import "regexp"

const fullScanTailBytes = 4096

var attackIndicatorPatterns = []string{
	`<script`,
	`javascript:`,
	`on\w+=`,
	`SELECT\s+.{0,50}?\s+FROM`,
	`UNION\s+SELECT`,
	`\.\./`,
	`eval\s*\(`,
	`exec\s*\(`,
	`system\s*\(`,
	`<\?php`,
	`<%`,
	`{{`,
	`{%`,
	`<iframe`,
	`<object`,
	`<embed`,
	`onerror\s*=`,
	`onload\s*=`,
	`\$\{`,
	`\\x[0-9a-fA-F]{2}`,
	`%[0-9a-fA-F]{2}`,
	"`",
	`\$\(`,
	`[;&|]`,
	`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
}

var compiledIndicators []*regexp.Regexp

func init() {
	for _, p := range attackIndicatorPatterns {
		compiledIndicators = append(compiledIndicators, regexp.MustCompile(`(?i)`+p))
	}
}

func extractAttackRegions(t scanText, maxContentLength int) [][2]int {
	maxRegions := maxContentLength / 100
	if maxRegions > 100 {
		maxRegions = 100
	}
	var regions [][2]int
	for _, re := range compiledIndicators {
		locs := re.FindAllStringIndex(t.s, maxRegions)
		for _, loc := range locs {
			start := t.runeOff(loc[0]) - 100
			if start < 0 {
				start = 0
			}
			end := t.runeOff(loc[1]) + 100
			if end > t.n {
				end = t.n
			}
			regions = append(regions, [2]int{start, end})
		}
		if len(regions) >= maxRegions {
			break
		}
	}
	if len(regions) == 0 {
		return nil
	}
	sortRegions(regions)
	merged := [][2]int{regions[0]}
	for _, r := range regions[1:] {
		last := &merged[len(merged)-1]
		if r[0] <= last[1] {
			if r[1] > last[1] {
				last[1] = r[1]
			}
		} else {
			merged = append(merged, r)
		}
	}
	if len(merged) > maxRegions {
		merged = merged[:maxRegions]
	}
	return merged
}

func sortRegions(regions [][2]int) {
	for i := 1; i < len(regions); i++ {
		for j := i; j > 0; j-- {
			if regions[j][0] < regions[j-1][0] || (regions[j][0] == regions[j-1][0] && regions[j][1] < regions[j-1][1]) {
				regions[j], regions[j-1] = regions[j-1], regions[j]
			} else {
				break
			}
		}
	}
}

func extractAndConcatenateAttackRegions(t scanText, regions [][2]int, budget int) string {
	out := make([]rune, 0, budget)
	remaining := budget
	for _, r := range regions {
		chunkLen := r[1] - r[0]
		if chunkLen > remaining {
			chunkLen = remaining
		}
		out = append(out, t.runes(r[0], r[0]+chunkLen)...)
		remaining -= chunkLen
		if remaining <= 0 {
			break
		}
	}
	return string(out)
}

func consumeGap(t scanText, lastEnd, start, gapBudget int) (string, int) {
	gapLen := start - lastEnd
	if gapLen <= gapBudget {
		return t.str(lastEnd, start), gapBudget - gapLen
	}
	chunkLen := gapBudget - 1
	piece := ""
	if chunkLen > 0 {
		piece = t.str(lastEnd, lastEnd+chunkLen)
	}
	return piece + " ", 0
}

func buildResultWithAttackRegionsAndContext(t scanText, regions [][2]int, budget int) string {
	attackLength := 0
	for _, r := range regions {
		attackLength += r[1] - r[0]
	}
	gapBudget := budget - attackLength
	parts := make([]string, 0, len(regions)*2+1)
	lastEnd := 0
	for _, r := range regions {
		start, end := r[0], r[1]
		if lastEnd < start && gapBudget > 0 {
			piece, gb := consumeGap(t, lastEnd, start, gapBudget)
			gapBudget = gb
			parts = append(parts, piece)
		}
		parts = append(parts, t.str(start, end))
		lastEnd = end
	}
	if lastEnd < t.n && gapBudget > 0 {
		tailLen := t.n - lastEnd
		if tailLen > gapBudget {
			tailLen = gapBudget
		}
		parts = append(parts, t.str(lastEnd, lastEnd+tailLen))
	}
	out := ""
	for _, p := range parts {
		out += p
	}
	return out
}

func capWithTail(rs []rune, maxFullScanBytes int) string {
	tail := fullScanTailBytes
	if tail > maxFullScanBytes {
		tail = maxFullScanBytes
	}
	headLen := maxFullScanBytes - tail
	out := make([]rune, 0, maxFullScanBytes)
	out = append(out, rs[:headLen]...)
	out = append(out, rs[len(rs)-tail:]...)
	return string(out)
}
