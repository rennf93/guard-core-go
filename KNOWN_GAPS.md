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
