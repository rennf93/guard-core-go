Release Notes
=============

___

Unreleased
----------

### Fixed

- **The request body is now scanned: urlencoded forms, multipart parts with binary islands, and JSON walks.** `detectThreat` previously only scanned the URL path, query parameters, and headers, so every attack that arrived inside a request body was invisible; the pipeline now reads the buffered request body (capped at `Detection.MaxBodyInspectBytes`), routes it by content type, and scans every extracted value with the Python engine's context labels: urlencoded field names and values (`request_body`, `request_body:form_field`), multipart labels and entries (`request_body:multipart_field`, with RFC 7578 filename detection, part headers, and the `filename="..."` entry the file-upload rows match on), JSON bodies walked depth-first in insertion order (keys checked against `excluded_detection_body_fields` and the mongo-operator registry, leaves scanned like the reference), and plain or unknown bodies as one whole `request_body` value. Embedded JSON inside form or multipart field values walks first with the `:embedded_json` leaf suffix, exactly like the reference's embedded-JSON-first order. File-part payloads that are binary-like (artifact characters fill at least a fifth of the part) are reduced to printable runs of at least the new `DetectionBinaryMinRunLength` field (default 16, validated to `[4, 1024]` like the Python pydantic constraint) and each island is scanned on its own, so compressed uploads stop producing attack-shaped noise while text embedded in uploads still detects; whole-body fallback scans are never island-reduced. The multipart scanner is a line-based port of the Python email feedparser tolerances (raw header names and case, folded header values, colonless lines joining the payload, preamble/epilogue, nested `multipart/*` containers walked in place, missing final boundary tolerated, zero leaf parts falling back to the whole-body blob scan). Parity with upstream guard-core commit `5f399234`.
- **Recon path rows now require a leading separator on query and body values.** Whole-value recon rows whose leading path separator is optional (the extension-path row plus the product/config/doc rows such as `default`, `sap`, `actuator`, `cgi-bin`, `README.md`, `credentials.json`) no longer flag ordinary bare-word field values in `query_param` and `request_body` contexts: outside `url_path`/`unknown` contexts the matched value must itself start with `/` or `\` to count as a recon probe. Separator-prefixed probe values (`/default.asp`, `/actuator/health`, `/cgi-bin/test.cgi`) and bare words used as the URL path still detect. Parity with upstream guard-core issue #115 (fix PR #116); the set of affected rows is derived from the pattern table by the same optional-separator anchor rule as the Python engine.
- **Display redaction collapses the whole value when the JSON depth cap trips.** A header or blob whose JSON nesting reaches the display-redaction depth cap (32, matching Python's `detection_max_json_depth` default) now redacts to a single `[REDACTED]` instead of emitting a huge half-redacted structure; nesting under the cap keeps the in-place redaction shape. Parity with upstream guard-core commit `8bae9459`.
- **Console-safe activity log lines.** The log-bound `Reason` and `TriggerInfo` fields (detection-derived text such as matched-pattern previews and body excerpts) are escaped to pure ASCII: literal `\n`/`\r`/`\t` escapes, `\xNN` for raw invalid UTF-8 bytes (the counterpart of Python's surrogate-escaped bytes), and `\uXXXX` for other control or non-ASCII characters, so log lines can never break on legacy console encodings such as Windows cp1252. The block stash, block hook payloads, and threat `match` reporting values are untouched. Parity with upstream guard-core commit `f5d53ca5`.

___

v4.0.4 (2026-09-24)
-------------------

Full parity with guard-core 4.0.4, binary-noise gates, and the /v4 module path (v4.0.4)
---------------------------------------------------------------------------------------

### Breaking Changes

- **Import paths now end in `/v4`.** The module path is `github.com/rennf93/guard-core-go/v4` and the release tag is `v4.0.4`; Go modules reject a `v4+` tag unless the module path carries the `/v4` suffix, so the migration is mandatory for this release to be fetchable. Update every import from `github.com/rennf93/guard-core-go/guardcore` to `github.com/rennf93/guard-core-go/v4/guardcore` (and the same for the `examples/...` internal packages). Installation is now `go get github.com/rennf93/guard-core-go/v4@v4.0.4`. The earlier `v0.1.0` tag was a burned pre-release snapshot of the port and remains on the un-suffixed path.

### Added

- **Full check parity with the Python guard-core 4.0.4 engine: 17/17 security checks.** The port now covers the complete check catalogue of the Python engine, including the 4.0.x additions.
- **Binary-noise gates for detection, including the SQLi comment-terminator binary gate.** Pattern sources prone to firing inside text-decoded binary bodies (PDFs, compressed streams) are registered in a noise-prone registry and gated by binary-density analysis, while genuine ASCII-region matches still detect. The SQLi comment-terminator source joins the registry in this release (parity with upstream guard-core `f5d53ca5`): the pattern's apostrophe-plus-whitespace-before-`--` shape routinely matched `0x27 0x0A 0x2D 0x2D`-style byte runs inside binary content.
- **Corpus harmonization with guard-core 4.0.3/4.0.4.** The conformance corpus tracks the Python engine's fixtures at spec 4.0.3/4.0.4, including binary-body vectors, so the two engines are validated against the same detection expectations.
- **Interop harness at 82/82.** The cross-implementation runner (`go test -tags interop`) executes the Python-engine fixture corpus against the Go engine with full agreement.

### Changed

- **Makefile harmonized with the Python guard family.** `install`, `test` (unit plus `-tags integration` in docker), `lint` (`gofmt` check plus `go vet`), `bump-version` (via `.github/scripts/bump_version.py`, which scaffolds this changelog) and `clean` match the conventions used across the Python guard repos.

___
