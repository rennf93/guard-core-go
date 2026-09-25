package guardcore

// Display/logging parity tests with guard-core 4.0.4:
//   - depth-capped display redaction (upstream commit 8bae9459): a JSON
//     header whose nesting exceeds the depth cap collapses to the
//     whole-value [REDACTED] placeholder instead of a huge half-redacted
//     structure; under-cap behavior is unchanged.
//   - console-safe log lines (upstream commit f5d53ca5): the log-bound
//     Reason/TriggerInfo text is escaped to pure ASCII.

import (
	"bytes"
	"strings"
	"testing"
)

// nestedJSON wraps leaf in levels-1 single-key containers, so with a "{}"
// leaf the total container depth equals levels.
func nestedJSON(levels int, leaf string) string {
	for i := 1; i < levels; i++ {
		leaf = `{"a":` + leaf + `}`
	}
	return leaf
}

func TestJSONRedactTextDepthCap(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		sensitive map[string]bool
		want      string
	}{
		{
			name:      "deep nesting past the cap collapses whole value even with nothing sensitive",
			text:      nestedJSON(40, "{}"),
			sensitive: nil,
			want:      RedactedPlaceholder,
		},
		{
			name:      "deep nesting with sensitive content collapses whole value",
			text:      nestedJSON(40, `{"password":"hunter2"}`),
			sensitive: map[string]bool{"password": true},
			want:      RedactedPlaceholder,
		},
		{
			name:      "31 container levels stay under the cap and stay unchanged",
			text:      nestedJSON(31, "{}"),
			sensitive: nil,
			want:      "",
		},
		{
			name:      "32 container levels trip the cap",
			text:      nestedJSON(32, "{}"),
			sensitive: nil,
			want:      RedactedPlaceholder,
		},
		{
			name:      "shallow nesting keeps in-place redaction",
			text:      nestedJSON(5, `{"password":"hunter2"}`),
			sensitive: map[string]bool{"password": true},
			want:      `{"a":{"a":{"a":{"a":{"password":"[REDACTED]"}}}}}`,
		},
	}
	for _, tc := range cases {
		if got := jsonRedactText(tc.text, tc.sensitive); got != tc.want {
			t.Errorf("%s: jsonRedactText = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRedactBlobForDisplayDeepJSONCollapsesWholeValue(t *testing.T) {
	if got := RedactBlobForDisplay(nestedJSON(40, `{"api_key":"k"}`), nil, nil, nil); got != RedactedPlaceholder {
		t.Fatalf("deep json blob must collapse to the whole-value placeholder, got %q", got)
	}
	// Under the cap the blob keeps the in-place redaction shape.
	got := RedactBlobForDisplay(nestedJSON(5, `{"api_key":"k"}`), nil, nil, nil)
	want := `{"a":{"a":{"a":{"a":{"api_key":"[REDACTED]"}}}}}`
	if got != want {
		t.Fatalf("shallow json blob redaction: got %q, want %q", got, want)
	}
}

func TestSanitizeForLogPureASCII(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty", "", ""},
		{"plain ascii unchanged", "plain ascii 123", "plain ascii 123"},
		{"newline escaped", "line1\nline2", `line1\nline2`},
		{"tab and carriage return escaped", "a\tb\rc", `a\tb\rc`},
		{"nul control char unicode escaped", "a\x00b", `a\u0000b`},
		{"delete char unicode escaped", "\x7f", `\u007f`},
		{"latin accent unicode escaped", "caf\u00e9", `caf\u00e9`},
		{"cjk unicode escaped", "\u65e5\u672c\u8a9e", `\u65e5\u672c\u8a9e`},
		{
			// The upstream PDF-prefix fixture: 0xc7 0x8f is a valid UTF-8
			// sequence (U+01CF) while 0xa2 is a lone byte; Python's
			// surrogateescape sanitizer renders the identical escapes.
			name: "pdf binary preview",
			in:   "%PDF\n%\xc7\x8f\xa2",
			want: `%PDF\n%\u01cf\xa2`,
		},
	}
	for _, tc := range cases {
		if got := sanitizeForLog(tc.in); got != tc.want {
			t.Errorf("%s: sanitizeForLog(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
	for _, tc := range cases {
		got := sanitizeForLog(tc.in)
		for i := 0; i < len(got); i++ {
			if got[i] >= 0x80 {
				t.Fatalf("%s: output must be pure ASCII, got %q", tc.name, got)
			}
		}
	}
}

func TestLogActivitySuspiciousReasonIsConsoleSafe(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	LogActivity(req, LogOptions{
		Logger:      captureLogger(&buf),
		LogType:     "suspicious",
		Reason:      "bad \x00 reason caf\u00e9 \n next",
		TriggerInfo: "custom_validation",
		Level:       "WARNING",
		PassiveMode: false,
		CheckName:   "custom_validators",
	})
	out := buf.String()
	if !strings.Contains(out, `Reason: bad \u0000 reason caf\u00e9 \n next - Headers:`) {
		t.Fatalf("suspicious line must carry the ascii-escaped reason: %q", out)
	}
	// The block stash keeps the raw reason; only the log line is escaped.
	if stash := req.State().BlockStash; stash == nil || stash.Reason != "bad \x00 reason caf\u00e9 \n next" {
		t.Fatalf("block stash must keep the raw reason, got %+v", stash)
	}
}

func TestLogActivityPassiveTriggerIsConsoleSafe(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	LogActivity(req, LogOptions{
		Logger:      captureLogger(&buf),
		LogType:     "suspicious",
		Reason:      "matched",
		TriggerInfo: "trig\u2028ger\nline",
		Level:       "WARNING",
		PassiveMode: true,
		CheckName:   "suspicious_activity",
	})
	out := buf.String()
	if !strings.Contains(out, `Trigger: trig\u2028ger\nline - Headers:`) {
		t.Fatalf("passive suspicious line must carry the ascii-escaped trigger: %q", out)
	}
}

func TestLogActivityGenericReasonIsConsoleSafe(t *testing.T) {
	var buf bytes.Buffer
	req := newTestRequest(t, nil)
	LogActivity(req, LogOptions{
		Logger:  captureLogger(&buf),
		LogType: "debug",
		Reason:  "why\u0001",
		Level:   "DEBUG",
	})
	if got := buf.String(); !strings.Contains(got, `Details: why\u0001 - Headers:`) {
		t.Fatalf("generic line must carry the ascii-escaped reason: %q", got)
	}
}
