# Roadmap and known gaps

This port tracks the Python `guard-core` engine. Behavior that is implemented
differently, or deferred, is listed here (see `KNOWN_GAPS.md` in the repository
for the detailed per-milestone notes).

## Deferred

- **Agent event pipeline** - `EnableAgent` is fail-closed; the `OnBlock` hook
  and `RateLimitManager.SetAgentHandlerHook` are the seams until
  [guard-agent-go](https://github.com/rennf93/guard-agent-go) integration
  lands.
- **Request body scanning** - the pipeline's suspicious-activity check scans
  the URL path, query parameters, and headers. Request bodies are not fed to
  the detector yet, so payloads carried solely in a body go unflagged.
- **Security events** - `ip_banned`, `ip_unbanned`, `rate_limited`,
  `cloud_blocked`, and middleware lifecycle events are not emitted yet.
- **GeoIP** - `WhitelistCountries` / `BlockedCountries` and geographic rate
  limits are fail-closed unsupported options.
- **Behavioral rules** - `GlobalBehaviorRules` and `EnableDynamicRules` are
  fail-closed unsupported options.
- **CORS** - `EnableCORS` is fail-closed; enforce CORS at your edge or in your
  adapter for now.

## Intentional differences

- `cloud_ip_refresh_interval` is clamped to `[60, 86400]` instead of rejecting
  out-of-range values.
- The custom-validators block hook fires with the validator's status code
  (spec 03 prose semantics).
- Cloud range refreshes use an injectable clock (`nowFunc`) for testability.

## Notes

- Ban expiry strings may differ in trailing digits from Python at epoch-scale
  doubles while remaining wire-equivalent.
- IPv6 `::ffff:`-mapped network CIDRs may render dotted-quad in Go.
- `reset` operations use Redis `KEYS` (spec-permitted); fine for admin
  tooling, avoid in hot paths.
