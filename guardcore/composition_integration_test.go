//go:build integration

package guardcore

import (
	"os"
	"testing"
)

func newIntegrationEngine(t *testing.T, mutate func(*SecurityConfig)) *Engine {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	cfg := DefaultSecurityConfig()
	cfg.EnableRedis = true
	cfg.RedisURL = "redis://" + host + ":6379"
	cfg.RedisPrefix = "guard_core_test:"
	cfg.RedisFailOpen = false
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("engine initialize: %v", err)
	}
	t.Cleanup(func() {
		_, _ = engine.Redis.DeletePattern("banned_ips:*")
		_, _ = engine.Redis.DeletePattern("rate_limit:rate:*")
		_ = engine.Close()
	})
	return engine
}

func TestIntegrationEngineStartupWiring(t *testing.T) {
	engine := newIntegrationEngine(t, nil)
	if engine.RateLimit.scriptSHA == "" {
		t.Fatal("rate limit Lua script must be loaded by Engine.Initialize")
	}
	bannedIP := "203.0.113.50"
	applied, err := engine.Ban.Ban(bannedIP, 120, "integration-test")
	if err != nil || !applied {
		t.Fatalf("ban not applied: %v %v", applied, err)
	}
	if !engine.Ban.IsIPBanned(bannedIP) {
		t.Fatal("ban must be visible through the engine ban manager")
	}
	req := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = bannedIP
	})
	resp := engine.Check(req)
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != IPBanBlockedMessage {
		t.Fatalf("banned IP must be blocked with 403 %q, got %+v", IPBanBlockedMessage, resp)
	}
	if err := engine.Ban.Unban(bannedIP); err != nil {
		t.Fatalf("unban: %v", err)
	}
	if resp := engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = bannedIP
	})); resp != nil {
		t.Fatalf("unbanned IP must pass, got %+v", resp)
	}
}
