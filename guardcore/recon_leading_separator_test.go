package guardcore

// Port of tests/test_sus_patterns/test_recon_bare_word_context.py
// (guard-core upstream issue #115, fix PR #116): whole-value recon rows
// whose leading path separator is optional must not flag ordinary bare-word
// values in query or body contexts, while separator-prefixed probe values in
// those contexts and bare words used as the URL path stay recon.

import (
	"strings"
	"testing"
)

// reconBareWords are ordinary field values matched by the whole-value recon
// rows when the leading "/" is optional: product names, enum values, file
// names.
var reconBareWords = []string{
	"default",
	"SAP",
	"ise",
	"language",
	"autodiscover",
	"confluence",
	"actuator",
	"cgi-bin",
	"lms/db",
	"README.md",
	"CHANGELOG",
	"Makefile",
	"credentials.json",
	"report.asp",
}

var reconProbePaths = []string{
	"/default.asp",
	"/sap",
	"/actuator/health",
	"/cgi-bin/test.cgi",
	"/README.md",
}

// Note on the Python vector "\default": this port's main-view preprocessor
// decodes LDAP-style hex escapes ("\de" -> U+00DE), so "\default" never
// reaches the recon row in the only view that carries it, independent of the
// leading-separator gate (pre-existing divergence, deferred). The gate's
// backslash acceptance is pinned at the buildRegexThreat level below.

// reconValueContexts are the value contexts of the Python request fixtures:
// a query parameter, a JSON body field, a form body field, and a JSON value
// embedded in a query parameter (the ':embedded_json' leaf context).
var reconValueContexts = []string{
	"query_param",
	"request_body",
	"query_param:embedded_json",
}

func detectContext(content, context string) DetectResult {
	return Detect(content, "127.0.0.1", context)
}

func assertNoReconThreat(t *testing.T, content, context string) {
	t.Helper()
	result := detectContext(content, context)
	if result.IsThreat {
		t.Fatalf("content %q in context %q: unexpected threat (score=%v threats=%v)", content, context, result.ThreatScore, result.Threats)
	}
	if len(result.Threats) != 0 {
		t.Fatalf("content %q in context %q: expected zero threats, got %v", content, context, result.Threats)
	}
}

func assertReconThreat(t *testing.T, content, context string) {
	t.Helper()
	result := detectContext(content, context)
	if !result.IsThreat {
		t.Fatalf("content %q in context %q: expected recon detection (score=%v threats=%v)", content, context, result.ThreatScore, result.Threats)
	}
	found := false
	for _, threat := range result.Threats {
		if threat["category"] == "recon" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("content %q in context %q: expected a recon-category threat, got %v", content, context, result.Threats)
	}
}

func TestBareWordQueryOrBodyValueIsNotAReconProbe(t *testing.T) {
	for _, value := range reconBareWords {
		for _, context := range reconValueContexts {
			assertNoReconThreat(t, value, context)
		}
	}
}

func TestProbePathAsAQueryOrBodyValueIsStillRecon(t *testing.T) {
	for _, value := range reconProbePaths {
		for _, context := range reconValueContexts {
			assertReconThreat(t, value, context)
		}
	}
}

func TestBareWordAsTheURLPathIsStillRecon(t *testing.T) {
	for _, value := range []string{"default", "sap", "README.md", "actuator"} {
		assertReconThreat(t, "/"+value, "url_path")
	}
}

// TestReconGateAcceptsBackslashPrefixedProbe pins the gate's separator
// acceptance for the backslash form of the Python "\default" vector at the
// buildRegexThreat level: in a query context a match whose text starts with
// "\" must survive the leading-separator gate.
func TestReconGateAcceptsBackslashPrefixedProbe(t *testing.T) {
	source := ""
	for _, def := range patternTable {
		if def.Category == "recon" && stringsHasPrefix(def.Pattern, reconOptionalSeparatorAnchor) && strings.Contains(def.Pattern, "localstart") {
			source = def.Pattern
			break
		}
	}
	if source == "" {
		t.Fatalf("could not find the default/inicio recon row in the pattern table")
	}
	re := mustCompileI(source)
	tt := newScanText(`\default`)
	m, err := re.FindRunesMatchStartingAt(tt.rs, 0)
	if err != nil || m == nil {
		t.Fatalf("expected the recon row to match the backslash fixture (err=%v)", err)
	}
	rm := matchFromIndices(tt, m.Index, m.Index+m.Length, "")
	threat := buildRegexThreat(&compiledPattern{
		source:   source,
		re:       re,
		contexts: map[string]bool{"query_param": true},
		category: "recon",
	}, rm, "query_param", buildBinaryPrefix(tt))
	if threat == nil {
		t.Fatalf("backslash-prefixed probe must survive the leading-separator gate in a query context")
	}
	if threat["category"] != "recon" {
		t.Fatalf("expected a recon threat, got %v", threat)
	}
}

// TestReconOptionalSeparatorPatternSourcesDerivation pins the documented
// derivation: a recon row belongs to the set exactly when its source starts
// with the optional-separator anchor, so required-separator rows (\A[/\\]
// without the question mark) and rows without an \A anchor stay out.
func TestReconOptionalSeparatorPatternSourcesDerivation(t *testing.T) {
	for _, def := range patternTable {
		if def.Category != "recon" {
			if reconOptionalSeparatorPatternSources[def.Pattern] {
				t.Errorf("non-recon row must not be in the optional-separator set: %q", def.Pattern)
			}
			continue
		}
		want := stringsHasPrefix(def.Pattern, reconOptionalSeparatorAnchor)
		if got := reconOptionalSeparatorPatternSources[def.Pattern]; got != want {
			t.Errorf("recon row membership %v does not match the anchor-prefix derivation %v: %q", got, want, def.Pattern)
		}
	}
	required := 0
	for _, def := range patternTable {
		if def.Category == "recon" && stringsHasPrefix(def.Pattern, `\A[/\\]`) && !stringsHasPrefix(def.Pattern, reconOptionalSeparatorAnchor) {
			required++
			if reconOptionalSeparatorPatternSources[def.Pattern] {
				t.Errorf("required-separator recon row must be excluded from the set: %q", def.Pattern)
			}
		}
	}
	if required == 0 {
		t.Fatalf("expected the table to still contain required-separator recon rows")
	}
}
