# Conformance

The `conformance/` directory holds a fixture-driven parity suite: JSON cases
generated from the Python `guard-core` engine (spec 4.0.2) and replayed through
`guardcore.Detect` here.

## Suites

```text
benign, boundaries, cmd_injection, context_matrix, encoding,
inclusion_sensitive_recon, misc_injection, path_traversal, semantic,
sqli, xss
```

Each case asserts `IsThreat`, `ThreatScore` (rounded to 6 decimals), the
multiset of matched threats, original/processed lengths, and
`DetectionMethod`, so any detector change that would drift from the Python
engine fails CI.

## Running

```bash
go test ./conformance/...
```

The suite runs as part of the regular unit test job (no Redis required); the
CI workflow runs it on every push and pull request.
