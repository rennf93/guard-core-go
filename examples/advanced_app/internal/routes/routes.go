// Package routes holds the HTTP handlers of the advanced example, split by
// concern the way the Python advanced example splits routers.
package routes

import (
	"encoding/json"
	"log"
	"net/http"

	guardcore "github.com/rennf93/guard-core-go/guardcore"
)

// App carries the engine into handlers that need operational access (the
// admin routes drive the ban manager directly).
type App struct {
	Engine *guardcore.Engine
}

// Mux builds the full route table.
func Mux(app *App) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/", app.info)
	mux.HandleFunc("/health", app.health)
	mux.HandleFunc("/ready", app.ready)
	mux.HandleFunc("/echo", app.echo)
	mux.HandleFunc("/rate/burst", app.burst)
	mux.HandleFunc("/admin/banned", app.bannedCount)
	mux.HandleFunc("/admin/ban", app.ban)
	mux.HandleFunc("/admin/unban", app.unban)
	mux.HandleFunc("/test/xss", app.attackEcho)
	mux.HandleFunc("/test/sqli", app.attackEcho)
	mux.HandleFunc("/test/traversal", app.attackEcho)

	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}

func (a *App) info(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"app":     "guard-core-go advanced example",
		"routes":  []string{"/health", "/ready", "/echo", "/rate/burst", "/admin/*", "/test/*"},
		"engine":  "guardcore",
		"version": "1.0.0",
	})
}

// health and ready are excluded from the pipeline (config.ExcludePaths), so
// probes and orchestrator health checks never trip the guard.
func (a *App) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) ready(w http.ResponseWriter, _ *http.Request) {
	// Extend this with real dependency probes (Redis PING, cloud range
	// warmup) for your deployment.
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (a *App) echo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"echo":    true,
		"method":  r.Method,
		"path":    r.URL.Path,
		"headers": len(r.Header),
	})
}

// burst is limited by config.EndpointRateLimits (5 requests per 60 seconds),
// which this port enforces by exact request path.
func (a *App) burst(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"endpoint": "/rate/burst",
		"limit":    "5 requests per 60 seconds",
	})
}

// The /admin/* routes are registered on the engine's RouteRegistry with a
// RequiredHeaders guard (see cmd/server/main.go): the engine itself rejects
// calls missing the admin token with a 400 before these handlers run.

func (a *App) bannedCount(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"banned_ips":      a.Engine.Ban.BannedIPCount(),
		"banned_networks": a.Engine.Ban.BannedNetworkCount(),
	})
}

func (a *App) ban(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP      string `json:"ip"`
		Seconds int    `json:"seconds"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"ip\": ..., \"seconds\": ..., \"reason\": ...}"})
		return
	}
	if body.Seconds <= 0 {
		body.Seconds = 300
	}
	if body.Reason == "" {
		body.Reason = "manual ban via admin route"
	}
	created, err := a.Engine.Ban.Ban(body.IP, body.Seconds, body.Reason)
	if err != nil {
		log.Printf("admin ban %s failed: %v", body.IP, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ban failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip": body.IP, "seconds": body.Seconds, "created": created,
	})
}

func (a *App) unban(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"ip\": ...}"})
		return
	}
	if err := a.Engine.Ban.Unban(body.IP); err != nil {
		log.Printf("admin unban %s failed: %v", body.IP, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unban failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ip": body.IP, "status": "unbanned"})
}

// attackEcho handlers intentionally echo hostile payloads; the guard blocks
// the request before the handler runs, so reaching this code means detection
// was bypassed (defense in depth: do not log or store the payload).
// Payloads are passed as query parameters because this port does not scan
// request bodies yet (see docs/roadmap.md).
func (a *App) attackEcho(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"detected": false})
}
