package guardcore

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

const binaryContentRatioThreshold = 0.2

func looksLikeBinaryContent(content string) bool {
	if content == "" {
		return false
	}
	nonText := 0
	total := 0
	for _, r := range content {
		total++
		if r != '\t' && r != '\r' && r != '\n' && (r == 0xFFFD || !unicode.IsPrint(r)) {
			nonText++
		}
	}
	return float64(nonText)/float64(total) >= binaryContentRatioThreshold
}

var attackKeywords = map[string]map[string]bool{
	"xss":      setOf("script", "javascript", "onerror", "onload", "onclick", "onmouseover", "alert", "eval", "document", "cookie", "window", "location"),
	"sql":      setOf("select", "union", "insert", "update", "delete", "drop", "from", "where", "order", "group", "having", "concat", "substring", "database", "table", "column"),
	"command":  setOf("exec", "system", "shell", "cmd", "bash", "powershell", "wget", "curl", "nc", "netcat", "chmod", "chown", "sudo", "passwd"),
	"path":     setOf("etc", "passwd", "shadow", "hosts", "proc", "boot", "win", "ini"),
	"template": setOf("render", "template", "jinja", "mustache", "handlebars", "ejs", "pug", "twig"),
}

var attackKeywordOrder = []string{"xss", "sql", "command", "path", "template"}

func setOf(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

var attackStructures = map[string]string{
	"tag_like":       `<[^>]+>`,
	"function_call":  `\w{1,64}\s*\([^)]{0,256}\)`,
	"command_chain":  `[;&|]{1,2}`,
	"path_traversal": `\.{2,20}[/\\]`,
	"url_pattern":    `[a-z]{1,32}://`,
}

var attackStructureOrder = []string{"tag_like", "function_call", "command_chain", "path_traversal", "url_pattern"}

var structureRes = map[string]*regexp.Regexp{}

var wordTokenRE = regexp.MustCompile(`\b\w+\b`)

func init() {
	for name, pat := range attackStructures {
		structureRes[name] = regexp.MustCompile(`(?i)` + pat)
	}
}

func tagScanWindow(content string) string {
	idx := strings.LastIndex(content, ">")
	return content[:idx+1]
}

func semanticExtractTokens(content string) []string {
	rs := []rune(content)
	if len(rs) > 50000 {
		content = string(rs[:50000])
	}
	content = collapseSpaces(content)
	lower := strings.ToLower(content)
	tokens := wordTokenRE.FindAllString(lower, 1000)
	special := 0
	for _, name := range attackStructureOrder {
		scanContent := content
		if name == "tag_like" {
			scanContent = tagScanWindow(content)
		}
		matches := structureRes[name].FindAllString(scanContent, 10)
		tokens = append(tokens, matches...)
		special += len(matches)
		if special >= 50 {
			break
		}
	}
	if len(tokens) > 1000 {
		tokens = tokens[:1000]
	}
	return tokens
}

func collapseSpaces(content string) string {
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
	return b.String()
}

func calculateEntropy(content string) float64 {
	if content == "" {
		return 0.0
	}
	rs := []rune(content)
	if len(rs) > 10000 {
		rs = rs[:10000]
	}
	counts := map[rune]int{}
	for _, r := range rs {
		counts[r]++
	}
	length := float64(len(rs))
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

var semanticLayerPatterns = []*regexp.Regexp{
	regexp.MustCompile(`%[0-9a-fA-F]{2}`),
	regexp.MustCompile(`[A-Za-z0-9+/]{4,}={0,2}`),
	regexp.MustCompile(`(?:0x)?[0-9a-fA-F]{4,}`),
	regexp.MustCompile(`\\u[0-9a-fA-F]{4}`),
	regexp.MustCompile(`&[#\w]+;`),
}

func detectEncodingLayers(content string) int {
	rs := []rune(content)
	if len(rs) > 10000 {
		content = string(rs[:10000])
	}
	layers := 0
	for _, re := range semanticLayerPatterns {
		if re.MatchString(content) {
			layers++
		}
	}
	return layers
}

func getStructuralPatternBoost(attackType, content string) float64 {
	scanContent := content
	var re *regexp.Regexp
	switch attackType {
	case "xss":
		re = structureRes["tag_like"]
		scanContent = tagScanWindow(content)
	case "sql":
		re = regexp.MustCompile(`(?i)\b(?:union|select|from|where)\b`)
	case "command":
		re = regexp.MustCompile(`[;&|]`)
	case "path":
		re = structureRes["path_traversal"]
	default:
		return 0.0
	}
	if re.MatchString(scanContent) {
		return 0.3
	}
	return 0.0
}

func semanticAnalyze(content string) map[string]any {
	tokens := semanticExtractTokens(content)
	tokenSet := map[string]bool{}
	for _, t := range tokens {
		tokenSet[t] = true
	}
	probs := map[string]any{}
	for _, attackType := range attackKeywordOrder {
		keywords := attackKeywords[attackType]
		matches := 0
		for k := range keywords {
			if tokenSet[k] {
				matches++
			}
		}
		base := 0.0
		if len(keywords) > 0 {
			base = float64(matches) / float64(len(keywords))
		}
		score := base + getStructuralPatternBoost(attackType, content)
		if score > 1.0 {
			score = 1.0
		}
		probs[attackType] = score
	}
	patterns := extractSuspiciousPatterns(content)
	risk := codeInjectionRisk(content)
	return map[string]any{
		"attack_probabilities": probs,
		"entropy":              calculateEntropy(content),
		"encoding_layers":      detectEncodingLayers(content),
		"is_obfuscated":        detectObfuscation(content),
		"suspicious_patterns":  patterns,
		"code_injection_risk":  risk,
		"token_count":          len(tokens),
	}
}

var nonWordCharRE = regexp.MustCompile(`[^a-zA-Z0-9\s]`)
var longRunRE = regexp.MustCompile(`\S{100,}`)

func detectObfuscation(content string) bool {
	if looksLikeBinaryContent(content) {
		return false
	}
	if calculateEntropy(content) > 4.5 {
		return true
	}
	if detectEncodingLayers(content) > 2 {
		return true
	}
	n := len([]rune(content))
	specialCount := len(nonWordCharRE.FindAllString(content, -1))
	if float64(specialCount)/float64(maxInt(n, 1)) > 0.4 {
		return true
	}
	if longRunRE.MatchString(content) {
		return true
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func extractSuspiciousPatterns(content string) []map[string]any {
	patterns := []map[string]any{}
	for _, name := range attackStructureOrder {
		scanContent := content
		if name == "tag_like" {
			scanContent = tagScanWindow(content)
		}
		st := newScanText(scanContent)
		locs := structureRes[name].FindAllStringIndex(scanContent, -1)
		for _, loc := range locs {
			start := st.runeOff(loc[0])
			end := st.runeOff(loc[1])
			ctxStart := start - 20
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := end + 20
			ft := newScanText(content)
			if ctxEnd > ft.n {
				ctxEnd = ft.n
			}
			patterns = append(patterns, map[string]any{
				"type":     name,
				"pattern":  st.str(start, end),
				"position": start,
				"context":  ft.str(ctxStart, ctxEnd),
			})
		}
	}
	return patterns
}

var doubledBraceRE = regexp.MustCompile(`[\{\}].*[\{\}]`)
var funcCallRE = regexp.MustCompile(`\w{1,64}\s*\([^)]{0,256}\)`)
var dollarVarRE = regexp.MustCompile(`[$@]\w+`)
var operatorRunRE = regexp.MustCompile(`[=+\-*/]{2,}`)
var injectionKeywordREs = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\beval\b`),
	regexp.MustCompile(`(?i)\bexec\b`),
	regexp.MustCompile(`(?i)\bcompile\b`),
	regexp.MustCompile(`(?i)\b__import__\b`),
	regexp.MustCompile(`(?i)\bglobals\b`),
	regexp.MustCompile(`(?i)\blocals\b`),
}

func codeInjectionRisk(content string) float64 {
	risk := 0.0
	if doubledBraceRE.MatchString(content) {
		risk += 0.2
	}
	if funcCallRE.MatchString(content) {
		risk += 0.2
	}
	if dollarVarRE.MatchString(content) {
		risk += 0.1
	}
	if operatorRunRE.MatchString(content) {
		risk += 0.1
	}
	for _, re := range injectionKeywordREs {
		if re.MatchString(content) {
			risk += 0.2
			break
		}
	}
	if risk > 1.0 {
		risk = 1.0
	}
	return risk
}

func semanticThreatScore(analysis map[string]any) float64 {
	score := 0.0
	if probs, ok := analysis["attack_probabilities"].(map[string]any); ok && len(probs) > 0 {
		maxProb := 0.0
		for _, v := range probs {
			if f, ok := v.(float64); ok && f > maxProb {
				maxProb = f
			}
		}
		score += maxProb * 0.3
	}
	if obf, ok := analysis["is_obfuscated"].(bool); ok && obf {
		score += 0.2
	}
	if layers, ok := analysis["encoding_layers"].(int); ok && layers > 0 {
		s := float64(layers) * 0.1
		if s > 0.2 {
			s = 0.2
		}
		score += s
	}
	if risk, ok := analysis["code_injection_risk"].(float64); ok {
		score += risk * 0.2
	}
	if patterns, ok := analysis["suspicious_patterns"].([]map[string]any); ok && len(patterns) > 0 {
		s := float64(len(patterns)) * 0.05
		if s > 0.1 {
			s = 0.1
		}
		score += s
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}
