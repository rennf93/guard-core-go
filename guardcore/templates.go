package guardcore

import (
	"sort"
	"time"
)

const templateTimeout = 2000 * time.Millisecond

type region struct {
	start   int
	barrier int
	end     int
}

func templateRegions(t scanText, opening, closing string) []region {
	var out []region
	op := []rune(opening)
	cl := []rune(closing)
	cursor := 0
	for {
		start := indexOfRuneSeq(t.rs, op, cursor)
		if start == -1 {
			return out
		}
		bodyStart := start + len(op)
		barrier := indexOfRune(t.rs, cl[0], bodyStart)
		if barrier == -1 {
			return out
		}
		cursor = bodyStart
		if alt := barrier - len(op) + 1; alt > cursor {
			cursor = alt
		}
		if startsWithRuneSeq(t.rs, cl, barrier) {
			out = append(out, region{start: start, barrier: barrier, end: barrier + len(cl)})
		}
	}
}

func indexOfRuneSeq(rs []rune, seq []rune, from int) int {
	if from < 0 {
		from = 0
	}
	n := len(seq)
	for i := from; i+n <= len(rs); i++ {
		match := true
		for j := 0; j < n; j++ {
			if rs[i+j] != seq[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func indexOfRune(rs []rune, target rune, from int) int {
	if from < 0 {
		from = 0
	}
	for i := from; i < len(rs); i++ {
		if rs[i] == target {
			return i
		}
	}
	return -1
}

func lastIndexOfRuneFrom(rs []rune, target rune, before int) int {
	if before > len(rs) {
		before = len(rs)
	}
	for i := before - 1; i >= 0; i-- {
		if rs[i] == target {
			return i
		}
	}
	return -1
}

func startsWithRuneSeq(rs []rune, seq []rune, at int) bool {
	if at+len(seq) > len(rs) {
		return false
	}
	for j := range seq {
		if rs[at+j] != seq[j] {
			return false
		}
	}
	return true
}

func templateFrame(t scanText, opening, closing string, start, end int) (rmatch, bool) {
	var b []rune
	for _, r := range opening {
		b = appendRuneQuoted(b, r)
	}
	b = append(b, '[')
	b = append(b, '^')
	b = appendRuneQuoted(b, []rune(closing)[0])
	b = append(b, ']', '*')
	for _, r := range closing {
		b = appendRuneQuoted(b, r)
	}
	re, err := compileRE(string(b), 0, templateTimeout)
	if err != nil {
		return rmatch{}, false
	}
	return findFirstAt(re, t, start, end)
}

func appendRuneQuoted(b []rune, r rune) []rune {
	switch r {
	case '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$', '/', '-':
		return append(b, '\\', r)
	}
	return append(b, r)
}

var keywordIndicatorRE = mustCompile(`(?:system|exec|popen|eval|require|include)\s*\z`, 0, templateTimeout)

func templateKeywordMatches(t scanText, opening, closing string) []rmatch {
	var matches []rmatch
	for _, reg := range templateRegions(t, opening, closing) {
		body := scanText{s: t.str(reg.start+len(opening)+1, reg.barrier), rs: t.rs[reg.start+len(opening)+1 : reg.barrier], n: reg.barrier - reg.start - len(opening) - 1}
		if len(findAllMatches(keywordIndicatorRE, body)) == 0 {
			continue
		}
		if m, ok := templateFrame(t, opening, closing, reg.start, reg.end); ok {
			matches = append(matches, m)
		}
	}
	return matches
}

var dateIndicatorRE = mustCompile(`(?=\d{4}-\d{1,2}-\d{1,2}(?!\d))`, 0, templateTimeout)

func templateAfterDates(t scanText, opening string, start, barrier int) int {
	rs := t.rs
	lo := start + 2
	lastDate := -1
	for _, m := range findAllMatches(dateIndicatorRE, scanText{s: runeStr(rs[lo:barrier]), rs: rs[lo:barrier], n: barrier - lo}) {
		lastDate = m.start() + lo
	}
	if lastDate != -1 {
		return indexOfRuneSeq(rs, []rune(opening), lastDate+1)
	}
	return start
}

func templateExpressionMatches(t scanText, kind string) []rmatch {
	var opening, closing, indicatorSrc string
	switch kind {
	case "dollar":
		opening, closing, indicatorSrc = "${", "}", `@[\w.]+@|\b\w+\s*\(|(?<!\d)\d+\s*[*/%+\-]\s*\d+`
	case "curly":
		opening, closing, indicatorSrc = "{{", "}}", `@[\w.]+@|\b\w+\(\s*\)|(?<!\d)['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?`
	case "hash":
		opening, closing, indicatorSrc = "#{", "}", `@[\w.]+@|\b\w+\s*\(|(?<!\d)['\"]?\d+['\"]?\s*[*/%+\-]\s*['\"]?\d+['\"]?`
	case "asp":
		opening, closing, indicatorSrc = "<%", "%>", "system|exec|eval|`|Runtime|IO\\.|File\\.|Dir\\.|(?<!\\d)\\d+\\s*[-+*/]\\s*\\d+"
	}
	indicator := mustCompile(indicatorSrc, 0, templateTimeout)
	var matches []rmatch
	lastEnd := 0
	for _, reg := range templateRegions(t, opening, closing) {
		start := reg.start
		if start < lastEnd {
			continue
		}
		if kind == "curly" || kind == "hash" {
			start = templateAfterDates(t, opening, start, reg.barrier)
		}
		if start == -1 {
			continue
		}
		body := scanText{s: t.str(start+len(opening), reg.barrier), rs: t.rs[start+len(opening) : reg.barrier], n: reg.barrier - start - len(opening)}
		if len(findAllMatches(indicator, body)) == 0 {
			continue
		}
		if m, ok := templateFrame(t, opening, closing, start, reg.end); ok {
			matches = append(matches, m)
			lastEnd = reg.end
		}
	}
	return matches
}

var _ = sort.Ints
