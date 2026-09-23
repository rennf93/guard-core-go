Release Notes
=============

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
