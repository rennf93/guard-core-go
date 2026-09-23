# Fixture Corpus

Executable conformance data. The expected values in this corpus were generated
by running the reference engine (guard-core, enhanced/4.x detection path) —
never hand-written. `conformance.md` defines the authorship and drift rules.

## Layout

```
fixtures/
  cases/
    index.json            suite registry, engine version/commit, config knobs, comparison rules
    xss.json              one file per suite: inputs + expected verdicts
    sqli.json
    cmd_injection.json
    path_traversal.json
    inclusion_sensitive_recon.json
    misc_injection.json
    encoding.json
    semantic.json
    benign.json
    context_matrix.json
    boundaries.json
  tools/
    generate_fixtures.py  regenerates expected values from the reference engine
    run_fixtures.py       Python conformance runner; the template ports replicate
```

## Case schema

```json
{
  "id": "suite-unique-case-id",
  "input": {
    "content": "payload or benign string",
    "context": "url_path | query_param | header | request_body | unknown"
  },
  "expected": {
    "is_threat": false,
    "threat_score": 0.0,
    "threats": [
      {
        "type": "regex",
        "pattern": "<script[^>]*>[^<]*<\\/script\\s*>",
        "match": "<script>alert(1)</script>",
        "position": 0,
        "category": "xss",
        "weight": 1.0
      }
    ],
    "original_length": 25,
    "processed_length": 25,
    "detection_method": "enhanced"
  }
}
```

## Comparison rules (normative for port runners)

- `threats` are stored sorted by `(category, pattern, position, type)`.
  Runners MUST compare order-insensitively using the same canonical sort.
- Excluded from comparison: `execution_time` (and any timing-derived field),
  timeout counts, correlation ids. These are load-dependent.
- Floats are compared at 6-decimal precision.
- `processed_length` pins preprocessing behavior (decode expansion, truncation,
  attack-pattern preservation). Runners MUST NOT ignore it.
- `context` filters which patterns apply (section 06); `context_matrix.json`
  pins the filter across all five contexts.

## Port consumption

A port's conformance runner:

1. Loads `index.json`, verifies `spec_version` matches the version the port
   targets, aborts otherwise.
2. For each suite file, runs each `input` through the port's `detect`
   equivalent under the `config_knobs` recorded in `index.json` (ports with
   different knob names map them in their impl spec).
3. Compares per the rules above. Any difference is a failure with a case-id
   report.

## Regenerating (reference repo only)

```bash
uv run python specs/fixtures/tools/generate_fixtures.py
uv run python specs/fixtures/tools/run_fixtures.py
```

Curating inputs: edit the suite lists in `generate_fixtures.py`, regenerate,
then re-run the runner to confirm determinism. Expected values always come
from the engine.

## spec 4.0.3 additions

`binary_bodies.json` pins the binary-body noise gate (upstream commit
436d6f72): a zip-like binary blob produces zero threats, noise-prone matches
inside artifact-dense padding are discarded, and attacks hidden in binary
padding (padded webshell, pickle opcode stream, base64-fragmented multipart
part with a filename signature) are still caught, as are pure-text, accented
and non-Latin controls. The pure random-noise views from the upstream payload
constants are covered by each port's in-repo honesty test suite rather than
this corpus: full-entropy noise stress-tests decoder pipelines far outside
the noise gate, where the ports still carry pre-existing decoder divergences
(tracked separately).

Surrogateescape-decoded views are stored with surrogate code points mapped to
U+FFFD: JSON cannot carry lone surrogates (PHP json_decode rejects them, Go
maps them to U+FFFD), the ports' adapters deliver those bytes as U+FFFD
replacement characters anyway, and both code point classes are artifact
characters with one code point each, so verdicts, code point lengths and gate
decisions are identical on both representations.
