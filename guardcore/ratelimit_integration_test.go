//go:build integration

package guardcore

import (
	"os"
	"strconv"
	"testing"
	"time"
)

func newRateLimitIntegrationManager(t *testing.T, mutate func(*RateLimitConfig)) (*RateLimitManager, *RedisManager) {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	mgr := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Redis initialize failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = mgr.DeletePattern("rate_limit:rate:*")
		_, _ = mgr.DeletePattern("banned_ips:*")
		_ = mgr.Close()
	})
	cfg := DefaultRateLimitConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	rl := NewRateLimitManager(cfg, mgr, nil)
	rl.InitializeRedis(mgr)
	return rl, mgr
}

func TestIntegrationRateLimitLuaScriptLoaded(t *testing.T) {
	rl, mgr := newRateLimitIntegrationManager(t, nil)
	if rl.scriptSHA == "" {
		t.Fatal("script SHA must be cached at startup")
	}
	count, err := mgr.EvalSha(rl.scriptSHA, mgr.Prefix()+"rate_limit:rate:203.0.113.1", 1000.0, 60, 10)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1 (current hit included)", count)
	}
}

func TestIntegrationRateLimitBlocksOverLimitAndExpires(t *testing.T) {
	rl, _ := newRateLimitIntegrationManager(t, func(c *RateLimitConfig) {
		c.RateLimit = 3
		c.RateLimitWindow = 1
	})
	ip := "203.0.113.2"
	for i := 0; i < 3; i++ {
		outcome, err := rl.CheckRateLimit(ip, "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Blocked {
			t.Fatalf("hit %d blocked", i+1)
		}
	}
	outcome, err := rl.CheckRateLimit(ip, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Blocked || outcome.Count != 4 || outcome.StatusCode != 429 {
		t.Fatalf("outcome = %+v, want blocked 4th hit count 4 status 429", outcome)
	}
	if outcome.RetryAfter() != strconv.Itoa(1) {
		t.Errorf("Retry-After = %q", outcome.RetryAfter())
	}
	time.Sleep(2 * time.Second)
	outcome, err = rl.CheckRateLimit(ip, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("bucket must expire after 2 x window idle")
	}
}

func TestIntegrationRateLimitTTLIsTwiceWindow(t *testing.T) {
	rl, mgr := newRateLimitIntegrationManager(t, func(c *RateLimitConfig) {
		c.RateLimitWindow = 30
	})
	ip := "203.0.113.3"
	if _, err := rl.CheckRateLimit(ip, "", nil, nil); err != nil {
		t.Fatal(err)
	}
	ttl, err := mgr.PTTL(mgr.Prefix() + "rate_limit:rate:" + ip)
	if err != nil {
		t.Fatal(err)
	}
	if ttl <= 0 || ttl > 60*time.Second {
		t.Fatalf("TTL = %v, want <= 2 x 30s window", ttl)
	}
}

func TestIntegrationRateLimitEndpointBucketSeparateFromGlobal(t *testing.T) {
	rl, mgr := newRateLimitIntegrationManager(t, func(c *RateLimitConfig) {
		c.EndpointRateLimits["/ws"] = RateLimitEntry{Requests: 2, Window: 60}
	})
	ip := "203.0.113.4"
	for i := 0; i < 2; i++ {
		outcome, err := rl.CheckRateLimit(ip, "/ws", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Blocked {
			t.Fatalf("endpoint hit %d blocked", i+1)
		}
	}
	outcome, err := rl.CheckRateLimit(ip, "/ws", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.Blocked || outcome.Tier != "endpoint" {
		t.Fatalf("third endpoint hit must block: %+v", outcome)
	}
	outcome, err = rl.CheckRateLimit(ip, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("global bucket is independent of the endpoint bucket")
	}
	keys, err := mgr.Keys("rate_limit:rate:*")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %v, want endpoint-sha bucket + global bucket", keys)
	}
	wantSHA := mgr.Prefix() + "rate_limit:rate:" + ip + ":" + hashIdentitySegment("/ws")
	foundSHA := false
	for _, k := range keys {
		if k == wantSHA {
			foundSHA = true
		}
	}
	if !foundSHA {
		t.Fatalf("missing sha256-hex endpoint bucket %s among %v", wantSHA, keys)
	}
}

func TestIntegrationRateLimitNoScriptReload(t *testing.T) {
	rl, mgr := newRateLimitIntegrationManager(t, nil)
	if rl.scriptSHA == "" {
		t.Fatal("script must be loaded")
	}
	if err := mgr.client.ScriptFlush(mgr.ctx).Err(); err != nil {
		t.Fatal(err)
	}
	reloaded := false
	rl.OnScriptReload = func() { reloaded = true }
	outcome, err := rl.CheckRateLimit("203.0.113.5", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Blocked {
		t.Fatal("unexpected block")
	}
	if !reloaded {
		t.Error("NOSCRIPT must trigger script reload and event hook")
	}
	if rl.scriptSHA == "" {
		t.Error("SHA must be repopulated after reload")
	}
}

func TestIntegrationRateLimitPrimitivePipelineSharesGlobalBucket(t *testing.T) {
	rl, _ := newRateLimitIntegrationManager(t, func(c *RateLimitConfig) {
		c.RateLimit = 2
	})
	ip := "203.0.113.6"
	if ok, err := rl.CheckRateLimitByIP(ip, ""); err != nil || !ok {
		t.Fatalf("hit 1: %v %v", ok, err)
	}
	if ok, err := rl.CheckRateLimitByIP(ip, ""); err != nil || !ok {
		t.Fatalf("hit 2: %v %v", ok, err)
	}
	ok, err := rl.CheckRateLimitByIP(ip, "")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("hit 3 must be limited via the always-pipeline path")
	}
}

func TestIntegrationRateLimitPipelineFallbackCounts(t *testing.T) {
	rl, _ := newRateLimitIntegrationManager(t, func(c *RateLimitConfig) {
		c.RateLimit = 1
	})
	rl.scriptSHA = ""
	ip := "203.0.113.7"
	if ok, err := rl.CheckRateLimitByIP(ip, ""); err != nil || !ok {
		t.Fatalf("hit 1: %v %v", ok, err)
	}
	if ok, _ := rl.CheckRateLimitByIP(ip, ""); ok {
		t.Fatal("hit 2 must be limited via MULTI fallback reading count from position 3")
	}
}

func TestIntegrationRateLimitAutobanFlatThreshold(t *testing.T) {
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	mgr := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: "guard_core_test:", EnableRedis: true})
	if err := mgr.Initialize(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = mgr.DeletePattern("rate_limit:rate:*")
		_, _ = mgr.DeletePattern("banned_ips:*")
		_ = mgr.Close()
	})
	ban := NewIPBanManager(mgr, nil)
	cfg := DefaultRateLimitConfig()
	cfg.RateLimit = 1
	cfg.EnableRateLimitAutoBan = true
	cfg.EnableIPBanning = true
	rl := NewRateLimitManager(cfg, mgr, ban)
	rl.InitializeRedis(mgr)

	ip := "203.0.113.8"
	if ok, _ := rl.CheckRateLimitByIP(ip, ""); !ok {
		t.Fatal("hit 1 must pass")
	}
	for i := 0; i < 10; i++ {
		if ok, _ := rl.CheckRateLimitByIP(ip, ""); ok {
			t.Fatalf("violation %d must be limited", i+2)
		}
	}
	if !ban.IsIPBanned(ip) {
		t.Fatal("10 violations must cross the flat threshold and ban via Redis-backed manager")
	}
}
