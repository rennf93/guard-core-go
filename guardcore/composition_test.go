package guardcore

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeURLPath(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"/a/b", "/a/b", true},
		{"", "/", true},
		{"//a", "/a", true},
		{"/a/b/", "/a/b", true},
		{"/a/%41", "/a/A", true},
		{"/%2e%2e/b", "/b", true},
		{"/a/../../b", "/b", true},
		{"/..", "/", true},
		{"/%2f..%2fetc", "/etc", true},
		{"/a\\b", "/a/b", true},
		{"/a/.;junk", "/a", true},
		{"/a/..;junk", "/", true},
		{"/a;b/c", "/a;b/c", true},
		{"/%", "/%", true},
		{"/%2", "/%2", true},
		{"/%41%42", "/AB", true},
		{"/a/%ff", "", false},
		{"/%2525252525252e2e", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeURLPath(tc.raw)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("normalizeURLPath(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPathMatchesExclusions(t *testing.T) {
	cases := []struct {
		path     string
		entries  []string
		expected bool
	}{
		{"/docs", []string{"/docs"}, true},
		{"/docsx", []string{"/docs"}, false},
		{"/docs/api", []string{"/docs"}, true},
		{"/anything", []string{"/"}, true},
		{"/other", []string{"/docs", "/static"}, false},
		{"/static/x", []string{"/docs", "/static"}, true},
	}
	for _, tc := range cases {
		if got := pathMatchesExclusions(tc.path, tc.entries); got != tc.expected {
			t.Fatalf("pathMatchesExclusions(%q, %v) = %v, want %v", tc.path, tc.entries, got, tc.expected)
		}
	}
}

func TestNormalizeExclusionsRejectsUndecodableEntries(t *testing.T) {
	matcher := &exclusionMatcher{cfg: &SecurityConfig{ExcludePaths: []string{"/docs", "/%ff"}}}
	entries := matcher.current()
	if len(entries) != 1 || entries[0] != "/docs" {
		t.Fatalf("undecodable entry must be dropped, got %v", entries)
	}
}

func TestExclusionMatcherNormalizesEntries(t *testing.T) {
	matcher := &exclusionMatcher{cfg: &SecurityConfig{ExcludePaths: []string{"/docs/"}}}
	if !matcher.matches("/docs") || !matcher.matches("/docs/api") || matcher.matches("/docsx") {
		t.Fatal("entries must normalize before matching")
	}
}

func TestExclusionMatcherRecomputesOnSourceChange(t *testing.T) {
	cfg := &SecurityConfig{ExcludePaths: []string{"/one"}}
	matcher := &exclusionMatcher{cfg: cfg}
	if !matcher.matches("/one/x") || matcher.matches("/two") {
		t.Fatal("initial exclusions not honored")
	}
	cfg.ExcludePaths = []string{"/two"}
	if !matcher.matches("/two/x") || matcher.matches("/one/x") {
		t.Fatal("exclusion source change not picked up")
	}
}

func newCompositionConfig(t *testing.T, mutate func(*SecurityConfig)) *SecurityConfig {
	t.Helper()
	cfg := DefaultSecurityConfig()
	cfg.EnableRedis = false
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func TestNewEngineRejectsNilConfig(t *testing.T) {
	if _, err := NewEngine(nil); err == nil {
		t.Fatal("nil config must be rejected")
	}
}

func TestNewEngineRejectsInvalidConfig(t *testing.T) {
	cfg := DefaultSecurityConfig()
	cfg.RateLimit = 0
	_, err := NewEngine(cfg)
	if err == nil || !strings.Contains(err.Error(), "rate_limit") {
		t.Fatalf("invalid config must fail validation, got %v", err)
	}
}

func TestEngineCheckBlocksBannedIP(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, nil))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	applied, err := engine.Ban.Ban("203.0.113.7", 60, "unit-test")
	if err != nil || !applied {
		t.Fatalf("ban not applied: %v %v", applied, err)
	}
	resp := engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.7"
	}))
	if resp == nil || resp.StatusCode != 403 || string(resp.Body) != IPBanBlockedMessage {
		t.Fatalf("banned IP must be blocked with 403 %q, got %+v", IPBanBlockedMessage, resp)
	}
}

func TestEngineCheckPassesCleanRequest(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, nil))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if resp := engine.Check(newTestRequest(t, nil)); resp != nil {
		t.Fatalf("clean request must pass, got %+v", resp)
	}
}

func TestEngineCheckExclusionScopingKeepsIPBanEnforced(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.ExcludePaths = []string{"/public"}
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if _, err := engine.Ban.Ban("203.0.113.8", 60, "unit-test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	resp := engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = "/public/data"
		opts.ClientHost = "203.0.113.8"
	}))
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("banned IP must stay blocked on excluded paths, got %+v", resp)
	}
}

func TestEngineCheckExclusionScopingSkipsSuspicious(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.ExcludePaths = []string{"/public"}
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	excluded := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = "/public"
		opts.RawQuery = "q=<script>alert(1)</script>"
	})
	if resp := engine.Check(excluded); resp != nil {
		t.Fatalf("suspicious detection must be skipped in exclusion scope, got %+v", resp)
	}
	scoped := newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.Path = "/search"
		opts.RawQuery = "q=<script>alert(1)</script>"
	})
	resp := engine.Check(scoped)
	if resp == nil || resp.StatusCode != 400 || string(resp.Body) != SuspiciousBlockedMsg {
		t.Fatalf("same vector outside exclusions must be blocked, got %+v", resp)
	}
}

func TestEngineCheckRouteBypassAllSkipsPipeline(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, nil))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	engine.Routes.Register("open", func(rc *RouteConfig) {
		rc.BypassedChecks = []string{"all"}
	})
	if _, err := engine.Ban.Ban("203.0.113.9", 60, "unit-test"); err != nil {
		t.Fatalf("ban: %v", err)
	}
	resp := engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.9"
		state.GuardRouteID = "open"
	}))
	if resp != nil {
		t.Fatalf("bypass-all route must skip the pipeline, got %+v", resp)
	}
	resp = engine.Check(newTestRequest(t, func(opts *RequestOptions, state *RequestState) {
		opts.ClientHost = "203.0.113.9"
		state.GuardRouteID = "guarded"
	}))
	if resp == nil || resp.StatusCode != 403 {
		t.Fatalf("without bypass-all the ban must hold, got %+v", resp)
	}
}

func TestEngineCreateErrorResponseHonorsCustomMessages(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.CustomErrorResponses[403] = "custom denial"
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if resp := engine.CreateErrorResponse(403, "default"); string(resp.Body) != "custom denial" || resp.StatusCode != 403 {
		t.Fatalf("custom message must win, got %+v", resp)
	}
	if resp := engine.CreateErrorResponse(404, "default"); string(resp.Body) != "default" || resp.StatusCode != 404 {
		t.Fatalf("default message must apply without override, got %+v", resp)
	}
}

func TestEngineInitializeWithoutRedis(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.BlockCloudProviders = []string{"AWS"}
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	engine.Cloud.mu.Lock()
	engine.Cloud.testFetcher = func(string) (cloudRangeSet, error) {
		return newCloudRangeSet(), nil
	}
	engine.Cloud.mu.Unlock()
	defer func() {
		engine.Cloud.mu.Lock()
		engine.Cloud.testFetcher = nil
		engine.Cloud.mu.Unlock()
	}()
	if err := engine.Initialize(); err != nil {
		t.Fatalf("initialize without redis must succeed, got %v", err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("initialize must be idempotent, got %v", err)
	}
}

func TestEngineInitializeRedisFailClosed(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.EnableRedis = true
		c.RedisURL = "redis://127.0.0.1:1"
		c.RedisFailOpen = false
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	err = engine.Initialize()
	var redisErr *GuardRedisError
	if !errors.As(err, &redisErr) {
		t.Fatalf("unreachable redis with redis_fail_open=false must fail closed, got %v", err)
	}
}

func TestEngineInitializeRedisFailOpen(t *testing.T) {
	engine, err := NewEngine(newCompositionConfig(t, func(c *SecurityConfig) {
		c.EnableRedis = true
		c.RedisURL = "redis://127.0.0.1:1"
		c.RedisFailOpen = true
	}))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("redis_fail_open=true must not fail startup, got %v", err)
	}
}
