package guardcore

import (
	"sort"
	"time"

	"github.com/dlclark/regexp2"
)

type compiledPattern struct {
	source   string
	re       *regexp2P
	contexts map[string]bool
	category string
}

var globalPatterns []compiledPattern

func init() {
	timeout := 2000 * time.Millisecond
	for _, def := range patternTable {
		re, err := compileRE(def.Pattern, regexp2.IgnoreCase, timeout)
		if err != nil {
			continue
		}
		ctx := make(map[string]bool, len(def.Contexts))
		for _, c := range def.Contexts {
			ctx[c] = true
		}
		globalPatterns = append(globalPatterns, compiledPattern{source: def.Pattern, re: re, contexts: ctx, category: def.Category})
	}
}

func resolvePatternWeight(pattern, category string) float64 {
	if w, ok := weightOverrides[pattern]; ok {
		return w
	}
	return 1.0
}

type viewMode int

const (
	viewPlain viewMode = iota
	viewMain
	viewRaw
	viewURLDecoded
)

func isRawViewPattern(source string) bool        { return rawViewSources[source] }
func isURLDecodedViewPattern(source string) bool { return urlDecodedViewSources[source] }

func patternExcludedFromView(source string, mode viewMode) bool {
	isRaw := isRawViewPattern(source)
	isURL := isURLDecodedViewPattern(source)
	switch mode {
	case viewRaw:
		return isURL || !isRaw
	case viewURLDecoded:
		return isRaw || !isURL
	case viewMain:
		return isRaw || isURL
	}
	return false
}

var knownContexts = map[string]bool{
	"query_param": true, "header": true, "url_path": true, "request_body": true, "unknown": true,
}

func normalizeContext(context string) string {
	if context == "" {
		context = "unknown"
	}
	normalized := context
	if idx := indexByteRune(context, ':'); idx >= 0 {
		normalized = splitFirst(context)
	}
	if !knownContexts[normalized] {
		return "unknown"
	}
	return normalized
}

func splitFirst(s string) string {
	for i, r := range s {
		if r == ':' {
			return s[:i]
		}
	}
	return s
}

func indexByteRune(s string, target rune) int {
	for i, r := range s {
		if r == target {
			return i
		}
	}
	return -1
}

type windowedFinderFunc func(t scanText) []rmatch

var windowedFinders map[string]windowedFinderFunc
var scanWindowMatcherFuncs map[string]func(t scanText) []rmatch
var scanWindowBoundsCompiled map[string][]scanBound
var candidateValidators map[string]func(m rmatch, context string) bool

func init() {
	windowedFinders = map[string]windowedFinderFunc{
		cmdNewlineShellDashCSource: cmdInjectionShellDashCFinditer,
		ldapNullByteAttrSource: func(t scanText) []rmatch {
			return ldapNullByteAttrFinditer(t, ldapNullByteAttrCompiled, ldapNullByteTailRE)
		},
		ldapNullByteDecodedAttrSource: func(t scanText) []rmatch {
			return ldapNullByteAttrFinditer(t, ldapNullByteDecodedAttrCompiled, ldapNullByteDecodedTailRE)
		},
		quoteSpliceCandidateSource: quoteSpliceFinditer,
		pickleGlobalGenericSource:  pickleGlobalGenericFinditer,
		xmlPublicExternalDTDSource: xmlPublicExternalDTDFinditer,
	}
	scanWindowMatcherFuncs = map[string]func(t scanText) []rmatch{
		sqliLoadFileSource:                loadFileScanMatches,
		cmdDollarSubstSource:              cmdInjectionDollarScanMatches,
		fileUploadDangerousSource:         func(t scanText) []rmatch { return fileUploadScanMatches(t, fileUploadDangerousSource) },
		fileUploadDoubleSource:            func(t scanText) []rmatch { return fileUploadScanMatches(t, fileUploadDoubleSource) },
		fileUploadTruncationSource:        func(t scanText) []rmatch { return fileUploadScanMatches(t, fileUploadTruncationSource) },
		fileUploadDecodedTruncationSource: func(t scanText) []rmatch { return fileUploadScanMatches(t, fileUploadDecodedTruncationSource) },
		templateCurlyKeywordSource:        func(t scanText) []rmatch { return templateKeywordMatches(t, "{{", "}}") },
		templateDollarBraceCallSource:     func(t scanText) []rmatch { return templateExpressionMatches(t, "dollar") },
		templateCurlyCallSource:           func(t scanText) []rmatch { return templateExpressionMatches(t, "curly") },
		templatePercentKeywordSource:      func(t scanText) []rmatch { return templateKeywordMatches(t, "{%", "%}") },
		templateASPKeywordSource:          func(t scanText) []rmatch { return templateExpressionMatches(t, "asp") },
		sstiHashBraceShapeSource:          func(t scanText) []rmatch { return templateExpressionMatches(t, "hash") },
		globWildcardAtomSource:            globWildcardScanMatches,
	}
}

func init() {
	candidateValidators = map[string]func(m rmatch, context string) bool{
		legacyIPv4HostSource:                   legacyIPv4MatchIsBlocked,
		ldapWildcardChainSource:                func(m rmatch, context string) bool { return ldapWildcardChainIsInjection(m) },
		ldapWildcardEqualsSource:               func(m rmatch, context string) bool { return ldapWildcardChainIsInjection(m) },
		ldapParenBreakoutSource:                func(m rmatch, context string) bool { return ldapWildcardChainIsInjection(m) },
		ldapParenConjunctionSource:             func(m rmatch, context string) bool { return ldapParenConjunctionIsInjection(m) },
		gluedBacktickCandidateSource:           gluedBacktickPairIsInjection,
		sensitiveSourceExtensionPathSource:     func(m rmatch, context string) bool { return !sourceExtensionPathIsProbe(context) },
		gluedDollarSubstitutionCandidateSource: dollarSubstitutionPairIsInjection,
		braceExpansionCommandSource:            braceExpansionIsDangerousCommand,
		quoteSpliceCandidateSource:             quoteSpliceTokenIsDangerousCommand,
		globWildcardAtomSource:                 globWildcardTokenIsDangerousCommand,
		pickleGlobalGenericSource:              pickleGlobalCandidateIsInjection,
	}
}

func sourceExtensionPathIsProbe(context string) bool {
	return !stringsHasSuffix(context, embeddedJSONLeafContextSuffix)
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func init() {
	scanWindowBoundsCompiled = map[string][]scanBound{}
	for source, pairs := range scanWindowBounds {
		var bounds []scanBound
		for _, p := range pairs {
			bounds = append(bounds, scanBound{
				prefix: mustCompile(p[0], 0, windowTimeout),
				term:   mustCompile(p[1], 0, windowTimeout),
			})
		}
		scanWindowBoundsCompiled[source] = bounds
	}
}

func iterScanWindowMatches(p *compiledPattern, t scanText) []rmatch {
	switch p.source {
	case `<!DOCTYPE[^>\[]*\[[\s\S]*?<!ENTITY`:
		return xmlInternalEntityFinditer(t)
	}
	var out []rmatch
	for _, bound := range scanWindowBoundsCompiled[p.source] {
		out = append(out, boundedFinditer(p.re, t, bound)...)
	}
	return out
}

func checkRegexPatterns(t scanText, context string, enabledCategories map[string]bool, mode viewMode) ([]map[string]any, []string, []string) {
	var threats []map[string]any
	var matched []string
	var timeouts []string

	normalized := normalizeContext(context)
	validatorContext := normalized
	if stringsHasSuffix(context, embeddedJSONLeafContextSuffix) {
		validatorContext = normalized + embeddedJSONLeafContextSuffix
	}
	skipFilter := normalized == "unknown" || normalized == "request_body"

	for _, p := range globalPatterns {
		if patternExcludedFromView(p.source, mode) {
			continue
		}
		if !skipFilter && !p.contexts[normalized] {
			continue
		}
		if enabledCategories != nil && p.category != "custom" && !enabledCategories[p.category] {
			continue
		}
		threat, timeoutOccurred := checkRegexPattern(&p, t, validatorContext)
		if timeoutOccurred {
			timeouts = append(timeouts, p.source)
			if threat == nil {
				threat = buildTimeoutThreat(&p)
			}
		}
		if threat != nil {
			threats = append(threats, threat)
			matched = append(matched, p.source)
		}
	}
	return threats, matched, timeouts
}

func firstAcceptedThreat(p *compiledPattern, matches []rmatch, validatorContext string) map[string]any {
	for _, m := range matches {
		m.re = p.re
		if threat := buildRegexThreat(p, m, validatorContext); threat != nil {
			return threat
		}
	}
	return nil
}

func checkRegexPattern(p *compiledPattern, t scanText, validatorContext string) (map[string]any, bool) {
	if finder, ok := windowedFinders[p.source]; ok {
		return firstAcceptedThreat(p, finder(t), validatorContext), false
	}
	if fn, ok := scanWindowMatcherFuncs[p.source]; ok {
		return firstAcceptedThreat(p, fn(t), validatorContext), false
	}
	if _, ok := scanWindowBoundsCompiled[p.source]; ok {
		return firstAcceptedThreat(p, iterScanWindowMatches(p, t), validatorContext), false
	}
	matches, timeout := safeFindAll(p, t)
	threat := firstAcceptedThreat(p, matches, validatorContext)
	return threat, timeout
}

func safeFindAll(p *compiledPattern, t scanText) ([]rmatch, bool) {
	var out []rmatch
	pos := 0
	for pos <= t.n {
		m, err := p.re.FindStringMatchStartingAt(t.s, pos)
		if err != nil {
			return out, true
		}
		if m == nil {
			break
		}
		g1 := ""
		if g := m.GroupByNumber(1); g != nil && len(g.Captures) > 0 {
			g1 = g.String()
		}
		rm := matchFromIndices(t, m.Index, m.Index+m.Length, g1)
		rm.re = p.re
		out = append(out, rm)
		next := m.Index + m.Length
		if m.Length == 0 {
			next++
		}
		if next == pos {
			next++
		}
		pos = next
	}
	return out, false
}

func buildRegexThreat(p *compiledPattern, m rmatch, validatorContext string) map[string]any {
	if validator, ok := candidateValidators[p.source]; ok {
		if !validator(m, validatorContext) {
			return nil
		}
	}
	return map[string]any{
		"type":     "regex",
		"pattern":  p.source,
		"match":    sanitizeForReporting(m.text()),
		"position": m.start(),
		"category": p.category,
		"weight":   resolvePatternWeight(p.source, p.category),
	}
}

func buildTimeoutThreat(p *compiledPattern) map[string]any {
	return map[string]any{
		"type":     "pattern_timeout",
		"pattern":  p.source,
		"match":    "",
		"position": 0,
		"category": p.category,
		"weight":   resolvePatternWeight(p.source, p.category),
	}
}

func sanitizeForReporting(s string) string { return s }

var _ = sort.Ints
