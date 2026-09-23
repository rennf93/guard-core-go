# guard-core-go

Guard Core Go is the API security core engine for Go: a faithful port of the
Python `guard-core` engine. It contains all shared security logic and no
framework bindings.

## What it provides

- Penetration attempt detection (XSS, SQLi, command injection, path traversal,
  SSRF, NoSQL, template injection, deserialization, and more) with
  Python-engine-compatible semantics
- IP banning with auto-ban thresholds and per-threat-category tuning
- Distributed rate limiting backed by Redis (atomic Lua scripts) with
  endpoint-level overrides
- Cloud provider IP range blocking (AWS, GCP, Azure, DigitalOcean, Linode,
  Vultr)
- Route-scoped configuration (per-route rate limits, auth, header
  requirements, custom validators)
- Redis-backed state with fail-open / fail-secure modes
- A block hook (`OnBlock`) as the telemetry seam for agent wiring

## Ecosystem position

```text
guard-core-go (this repo)      <- Engine: all security logic lives here
├── nethttp-guard              <- Adapter: net/http middleware
├── gin-guard                  <- Adapter: gin middleware
├── echo-guard                 <- Adapter: echo (v4) middleware
└── fiber-guard                <- Adapter: fiber (v3) middleware
```

The engine is framework-agnostic by design: it operates on its own
`Request`/`Response` abstractions. Framework integration happens in the
adapter repositories above; each adapter translates native requests into
`guardcore.Request`, runs `Engine.Check`, and translates a non-nil
`guardcore.Response` verdict into a native response.

## Installation

```bash
go get github.com/rennf93/guard-core-go/v4@v4.0.4
```

Requires Go 1.25 or later.

## Quick start

```go
package main

import (
    "log"

    "github.com/rennf93/guard-core-go/v4/guardcore"
)

func main() {
    cfg := guardcore.DefaultSecurityConfig()
    engine, err := guardcore.NewEngine(cfg)
    if err != nil {
        log.Fatal(err)
    }
    if err := engine.Initialize(); err != nil {
        log.Fatal(err)
    }
    defer engine.Close()

    factory := guardcore.NewRequestFactory()
    req := factory.CreateRequest(guardcore.RequestOptions{
        Path:       "/api",
        Scheme:     "http",
        Host:       "example.com",
        Method:     "GET",
        ClientHost: "203.0.113.9",
    })

    if resp := engine.Check(req); resp != nil {
        log.Printf("blocked: %d %s", resp.StatusCode, resp.Body)
        return
    }
    log.Println("allowed")
}
```

A `nil` response from `Engine.Check` means the request is allowed; a non-nil
`guardcore.Response` carries the block verdict (status code, headers, body).

## Next steps

- [Usage](usage.md) - engine lifecycle, the request contract, and the managers
- [Configuration](configuration.md) - every `SecurityConfig` knob
- [Detection](detection.md) - the detector, categories, and tuning
- [Conformance](conformance.md) - parity against the Python engine fixtures
- [Roadmap](roadmap.md) - known divergences from the Python engine
