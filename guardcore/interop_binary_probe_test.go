//go:build interop

package guardcore

// Binary-body detect vector probe for the interop binary-vector runner
// (interop/go_php_binary_vectors.py in the guard-core reference checkout).
//
// Reads a JSON vector list from the path in INTEROP_VECTORS_INPUT (each
// vector: {"label": ..., "payload_b64": ...} with an optional "context"
// detect context, defaulting to "request_body:multipart_field"; the payload
// bytes are the raw request body bytes) and writes one verdict per vector to
// the path in INTEROP_VECTORS_OUTPUT:
//
//	{"label": ..., "is_threat": ..., "threat_score": ...,
//	 "threats": [{"category": ..., "pattern": ...}]}
//
// Body bytes become a Go string with invalid UTF-8 mapped to U+FFFD, the
// engine's own binary-body representation.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

func TestBinaryVectorProbe(t *testing.T) {
	inputPath := os.Getenv("INTEROP_VECTORS_INPUT")
	outputPath := os.Getenv("INTEROP_VECTORS_OUTPUT")
	if inputPath == "" || outputPath == "" {
		t.Fatal("INTEROP_VECTORS_INPUT and INTEROP_VECTORS_OUTPUT must be set")
	}
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read vectors input: %v", err)
	}
	var vectors []struct {
		Label      string `json:"label"`
		PayloadB64 string `json:"payload_b64"`
		Context    string `json:"context"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("vectors input is not valid JSON: %v", err)
	}

	type threatOut struct {
		Category string `json:"category"`
		Pattern  string `json:"pattern"`
	}
	out := make([]map[string]any, 0, len(vectors))
	for _, v := range vectors {
		payload, err := base64.StdEncoding.DecodeString(v.PayloadB64)
		if err != nil {
			t.Fatalf("vector %q payload_b64: %v", v.Label, err)
		}
		context := v.Context
		if context == "" {
			context = "request_body:multipart_field"
		}
		result := Detect(string(payload), "127.0.0.1", context)
		threats := make([]threatOut, 0, len(result.Threats))
		for _, threat := range result.Threats {
			category, _ := threat["category"].(string)
			pattern, _ := threat["pattern"].(string)
			threats = append(threats, threatOut{Category: category, Pattern: pattern})
		}
		sort.Slice(threats, func(i, j int) bool {
			if threats[i].Category != threats[j].Category {
				return threats[i].Category < threats[j].Category
			}
			return threats[i].Pattern < threats[j].Pattern
		})
		score := result.ThreatScore
		out = append(out, map[string]any{
			"label":           v.Label,
			"is_threat":       result.IsThreat,
			"threat_score":    score,
			"threats":         threats,
			"original_length": result.OriginalLength,
		})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("verdicts marshal failed: %v", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		t.Fatalf("verdicts write failed: %v", err)
	}
}
