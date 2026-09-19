# KNOWN_GAPS

Milestone 2a (state core: Redis surface, canonical IP, IP ban manager).

## Float-string expiry formatting

Python writes ban expiries as `str(time.time() + duration)` (repr of a
double: shortest round-trip decimal, exponent form only outside
~1e-4..1e16). The Go port uses `strconv.FormatFloat(expiry, 'f', -1, 64)`.
For epoch-scale values (~1.7e9) both produce a plain decimal shortest
round-trip string, so the format contract ("decimal float string,
parsed with float()") holds byte-exactly for equal doubles; the digits
themselves always differ in practice because the timestamps differ.

## IPv6 scope ids

Python `ipaddress` accepts IPv6 scope ids (`fe80::1%eth0`); Go
`netip.ParseAddr` also accepts zones, and the port renders a scoped
IPv4-mapped address as `::ffff:a.b.c.d%zone` to match Python's
`str(addr)`. Ordinary scoped link-local addresses render identically
(lowercase compressed). This path is untested against Python fixtures
and is outside the interop-critical set (ban keys canonicalize away
IPv4-mapped forms entirely).

## `ip_network` canonical string edge cases

CIDR ban keys use `netip.Prefix.Masked().String()`. For IPv4 and
ordinary IPv6 networks this matches `str(ipaddress.ip_network(x,
strict=False))` exactly (host bits cleared, lowercase compressed). The
rare IPv4-mapped IPv6 *network* form (e.g. `::ffff:10.0.0.0/104`),
which Python renders as `::ffff:a00:0/104`, may render in Go's
dotted-quad form; no reference reader consumes `banned_networks:*`
keys today (spec 08, discrepancy 3 / open question), so this does not
affect live interop.

## Key listing (reset)

The reference `reset` uses `KEYS`; the Go `DeletePattern` also uses
`KEYS` for observable parity (spec 08 says SCAN is acceptable). The
legacy-key migration uses `SCAN` as required.

## Events

`ip_banned` / `ip_unbanned` / `ip_ban_failed` security-event emission
(spec 09 Events) is not part of Milestone 2a; the ban manager carries
no agent handler yet. Event shapes are deferred to the pipeline
milestone.

# Milestone 2b (rate limiting)

## ZSET member stringification

The pipeline fallback writes the member as Go's
`strconv.FormatFloat(now, 'f', -1, 64)`; Python writes `str(current_time)`
(shortest round-trip repr). For epoch-scale doubles both render a plain
decimal shortest round-trip string, so members collapse/compare
identically for equal doubles; the digits can differ from Python's for
the same instant only in exotic cases. Spec 07 discrepancy 3 states the
wire float value is what matters; internal representation is not
observable.

## Identical-timestamp member collapse

Preserved per spec: hits recorded at the same float timestamp collapse
as one zset member (Lua `ZADD key now now`). The port does not uniquify
members.

## Fail-open warning flag

The once-per-process `redis_fail_open` warning is a package-level flag
(`rateLimitFailOpenWarned`), matching Python's module-level
`_redis_fail_open_warned`. It is exported only via a test hook
(`resetRateLimitFailOpenWarned`).

## Events deferred

`rate_limited` / `rate_limit_script_reloaded` security-event emission
(section 07 Events) needs the agent/event pipeline (future milestone);
the manager exposes the `OnScriptReload` hook the pipeline path will
wire up. Pipeline-tier `decorator_violation` /
`dynamic_rule_violation` middleware events are likewise out of scope
here (no middleware layer yet).

## RateLimitManager singleton

Python gates a module-level singleton (`RateLimitManager.__new__`);
the port exposes a plain struct (`NewRateLimitManager`) — process-wide
singleton policy belongs to the composition root, not the core type
(spec impl/go.md boundary: no hidden global constructors).

# Milestone 3c (request logging + custom checks)

## custom_validators on_block

Reference `ON_BLOCK_EXCLUDED_CHECK_NAMES` suppresses the pipeline block hook
for `custom_validators`, while spec 03 §custom_validators says the blocking
response "still fires the block hook". This port resolves the discrepancy by
NOT suppressing it: the check fires the hook itself (`fireBlockHookForced`)
with the raw validator response's status code, matching spec 03's prose.
The passive-mode dispatch still uses the reference suppression (no hook).

## Validator response passthrough

Like the reference, the validator's own `*Response` is returned as-is,
bypassing `create_error_response` custom messages. The reference applies
`middleware.response_factory.apply_modifier` only for `custom_request`; the
Go port has no response modifier yet, so `custom_request` also returns the
callback's response unmodified.

## Events

Middleware event emission (`EVENT_DECORATOR_VIOLATION`,
`EVENT_CUSTOM_REQUEST_CHECK`) is not ported, consistent with earlier
milestones; verdicts, statuses, logs, stash, and hook payloads are.
