//go:build integration

package guardcore

import (
	"os"
	"strconv"
	"testing"
	"time"
)

func newIntegrationRedis(t *testing.T) *RedisManager {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	url := "redis://" + host + ":6379"
	mgr := NewRedisManager(RedisConfig{URL: url, Prefix: "guard_core_test:", EnableRedis: true})
	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Redis initialize failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = mgr.DeletePattern("banned_ips:*")
		_, _ = mgr.DeletePattern("banned_networks:*")
		_ = mgr.Close()
	})
	return mgr
}

func TestIntegrationKeySchema(t *testing.T) {
	mgr := newIntegrationRedis(t)
	if err := mgr.SetKey("banned_ips", "203.0.113.9", "1735689600.123456", intPtr(60)); err != nil {
		t.Fatal(err)
	}
	value, err := mgr.GetKey("banned_ips", "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if value != "1735689600.123456" {
		t.Fatalf("round-trip mismatch: %q", value)
	}
	keys, err := mgr.Keys("banned_ips:203.0.113.9")
	if err != nil || len(keys) != 1 || keys[0] != "guard_core_test:banned_ips:203.0.113.9" {
		t.Fatalf("key schema mismatch: keys=%v err=%v", keys, err)
	}
	missing, err := mgr.GetKey("banned_ips", "203.0.113.99")
	if err != nil || missing != "" {
		t.Fatalf("miss must return empty string and nil error, got %q %v", missing, err)
	}
	ttl, err := mgr.PTTL("guard_core_test:banned_ips:203.0.113.9")
	if err != nil || ttl <= 0 || ttl > 61*time.Second {
		t.Fatalf("unexpected PTTL %v err=%v", ttl, err)
	}
}

func TestIntegrationTTLZeroPersists(t *testing.T) {
	mgr := newIntegrationRedis(t)
	if err := mgr.SetKey("banned_ips", "203.0.113.10", "persist-me", nil); err != nil {
		t.Fatal(err)
	}
	ttl, err := mgr.PTTL("guard_core_test:banned_ips:203.0.113.10")
	if err != nil || ttl != -1 {
		t.Fatalf("persist key must have PTTL -1, got %v err=%v", ttl, err)
	}
	if err := mgr.SetKey("banned_ips", "203.0.113.11", "persist-me-too", intPtr(0)); err != nil {
		t.Fatal(err)
	}
	ttl, err = mgr.PTTL("guard_core_test:banned_ips:203.0.113.11")
	if err != nil || ttl != -1 {
		t.Fatalf("ttl=0 must persist per spec 08, got %v err=%v", ttl, err)
	}
	_, _ = mgr.Delete("banned_ips", "203.0.113.10")
	_, _ = mgr.Delete("banned_ips", "203.0.113.11")
}

func TestIntegrationBanLifecycle(t *testing.T) {
	store := newIntegrationRedis(t)
	mgr := NewIPBanManager(store, []string{"10.99.0.0/16"})
	ok, err := mgr.Ban("[2001:DB8::AA]", 120, "integration")
	if err != nil || !ok {
		t.Fatalf("ban failed: ok=%v err=%v", ok, err)
	}
	value, err := store.GetKey("banned_ips", "2001:db8::aa")
	if err != nil {
		t.Fatal(err)
	}
	if value == "" {
		t.Fatal("canonical key not present in Redis")
	}
	if _, err := strconv.ParseFloat(value, 64); err != nil {
		t.Fatalf("stored expiry %q not a float string", value)
	}
	if !mgr.IsIPBanned("2001:db8::aa") {
		t.Error("banned IP not detected")
	}
	crossWorker := NewIPBanManager(store, nil)
	if !crossWorker.IsIPBanned("2001:db8::aa") {
		t.Error("second manager must see ban via Redis")
	}
	if err := mgr.Unban("2001:db8::aa"); err != nil {
		t.Fatal(err)
	}
	if mgr.IsIPBanned("2001:db8::aa") {
		t.Error("unbanned IP still banned")
	}
	refused, err := mgr.Ban("10.99.1.2", 60, "integration")
	if err != nil || refused {
		t.Error("trusted proxy ban must be refused without error")
	}
}

func TestIntegrationMigration(t *testing.T) {
	store := newIntegrationRedis(t)
	legacyKey := store.Prefix() + "banned_ips:[2001:DB8::BB]"
	if err := store.SetPX(legacyKey, "1735689600.5", 90*time.Second); err != nil {
		t.Fatal(err)
	}
	mgr := NewIPBanManager(store, nil)
	if err := mgr.InitializeRedis(store); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetKey("banned_ips", "[2001:DB8::BB]"); err != nil {
		t.Fatal(err)
	}
	keys, err := store.ScanMatch(store.Prefix() + "banned_ips:*")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k == legacyKey {
			t.Error("legacy key not migrated away")
		}
	}
	if _, err := store.GetKey("banned_ips", "2001:db8::bb"); err != nil {
		t.Fatal(err)
	}
	value, err := store.GetKey("banned_ips", "2001:db8::bb")
	if err != nil || value != "1735689600.5" {
		t.Fatalf("migrated value mismatch: %q err=%v", value, err)
	}
	ttl, err := store.PTTL(store.Prefix() + "banned_ips:2001:db8::bb")
	if err != nil || ttl <= 0 {
		t.Fatalf("migrated key missing TTL: %v err=%v", ttl, err)
	}
}

func TestIntegrationManagerReset(t *testing.T) {
	store := newIntegrationRedis(t)
	mgr := NewIPBanManager(store, nil)
	if _, err := mgr.Ban("203.0.113.20", 60, "integration"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Ban("203.0.113.21", 60, "integration"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reset(); err != nil {
		t.Fatal(err)
	}
	keys, err := store.Keys("banned_ips:*")
	if err != nil || len(keys) != 0 {
		t.Fatalf("reset left keys: %v err=%v", keys, err)
	}
}
