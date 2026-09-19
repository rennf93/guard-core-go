package guardcore

import "golang.org/x/text/unicode/norm"

const maxDecodeIterations = 16

type preprocessed struct {
	processed       string
	decoded         string
	budgetExhausted bool
}

func nfkcString(s string) string {
	return norm.NFKC.String(s)
}

type preprocessor struct {
	maxContentLength       int
	preserveAttackPatterns bool
	maxFullScanBytes       int
}

func newPreprocessor(cfg Config) *preprocessor {
	return &preprocessor{
		maxContentLength:       cfg.MaxContentLength,
		preserveAttackPatterns: cfg.PreserveAttackPatterns,
		maxFullScanBytes:       cfg.MaxBodyInspectBytes,
	}
}

func (p *preprocessor) decodeCommonEncodings(content string) (string, bool) {
	iterations := 0
	gunzipLeft := maxGunzipAttemptsPerPass
	exhausted := false
	for iterations < maxDecodeIterations {
		original := content
		content = decodeOverlongUTF8PercentRuns(content)
		decoded := urlUnquote(content)
		if decoded != content {
			content = decoded
		}
		decoded = htmlUnescape(content)
		if decoded != content {
			content = decoded
		}
		content = decodePercentUEscapes(content)
		content = decodeHexEscapes(content)
		content = decodeLDAPHexEscapes(content)
		content = decodeUnicodeEscapes(content)
		content = normalizeUnicode(content)
		content = decodeBase64Candidates(content, &gunzipLeft, p.maxFullScanBytes)
		if content == original {
			break
		}
		iterations++
		if iterations >= maxDecodeIterations {
			exhausted = true
		}
	}
	return stripSQLComments(content), exhausted
}

func (p *preprocessor) truncateSafely(content string) string {
	t := newScanText(content)
	if t.n <= p.maxFullScanBytes {
		return content
	}
	if !p.preserveAttackPatterns {
		return t.str(0, p.maxFullScanBytes)
	}
	regions := extractAttackRegions(t, p.maxContentLength)
	if len(regions) == 0 {
		return capWithTail(t.rs, p.maxFullScanBytes)
	}
	attackLength := 0
	for _, r := range regions {
		attackLength += r[1] - r[0]
	}
	if attackLength >= p.maxFullScanBytes {
		return extractAndConcatenateAttackRegions(t, regions, p.maxFullScanBytes)
	}
	return buildResultWithAttackRegionsAndContext(t, regions, p.maxFullScanBytes)
}

func (p *preprocessor) preprocessWithDecoded(content string) preprocessed {
	if content == "" {
		return preprocessed{}
	}
	decoded := normalizeUnicode(content)
	decoded, exhausted := p.decodeCommonEncodings(decoded)
	processed := removeNullAndControlBytes(decoded)
	processed = removeExcessiveWhitespace(processed)
	processed = p.truncateSafely(processed)
	return preprocessed{processed: processed, decoded: decoded, budgetExhausted: exhausted}
}

func (p *preprocessor) preprocessSignalPreserving(content string) string {
	if content == "" {
		return ""
	}
	content = normalizeUnicode(content)
	return p.truncateSafely(content)
}

func (p *preprocessor) preprocessURLDecodedNewlinePreserving(content string) (string, bool) {
	if content == "" {
		return "", false
	}
	content = normalizeUnicode(content)
	content, exhausted := p.decodeCommonEncodings(content)
	return p.truncateSafely(content), exhausted
}
