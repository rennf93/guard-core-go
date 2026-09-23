// Command server assembles the advanced example: tuned engine config, route
// registry, guard middleware, and graceful shutdown.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"

	"github.com/rennf93/guard-core-go/v4/examples/advanced_app/internal/config"
	"github.com/rennf93/guard-core-go/v4/examples/advanced_app/internal/guardmw"
	"github.com/rennf93/guard-core-go/v4/examples/advanced_app/internal/routes"
)

func main() {
	cfg, err := config.New()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("engine close: %v", err)
		}
	}()

	// Route registry: route IDs are attached to requests by the guard
	// middleware (below) and resolved by the engine's route_config check.
	//
	// Note on ported surface: this Go port enforces the following
	// route-scoped knobs: RequireHTTPS, MaxRequestSize,
	// AllowedContentTypes, RequiredHeaders, and authentication. Per-route
	// rate limits are NOT read by the pipeline yet; use
	// SecurityConfig.EndpointRateLimits (as done for /rate/burst) instead.
	adminToken := envOr("ADMIN_TOKEN", "admin-token-change-me")
	engine.Routes.Register("admin", func(rc *guardcore.RouteConfig) {
		rc.RequiredHeaders = guardcore.RequiredHeaders{
			{Name: "X-Admin-Token", Value: adminToken},
		}
	})

	app := &routes.App{Engine: engine}

	// Map paths to route IDs before the guard sees them.
	guard := guardmw.New(engine, map[string]string{
		"/admin/banned": "admin",
		"/admin/ban":    "admin",
		"/admin/unban":  "admin",
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           guard.Wrap(routes.Mux(app)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Println("advanced example listening on :8080 (nginx fronts this in compose)")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
