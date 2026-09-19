package guardcore

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRedis struct {
	mu     sync.Mutex
	data   map[string]fakeEntry
	prefix string
	fail   bool
}

type fakeEntry struct {
	value  string
	expiry time.Time
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{data: map[string]fakeEntry{}, prefix: "guard_core:"}
}

func (f *fakeRedis) Prefix() string    { return f.prefix }
func (f *fakeRedis) Enabled() bool     { return true }
func (f *fakeRedis) Initialize() error { return nil }
func (f *fakeRedis) Close() error      { return nil }

func (f *fakeRedis) full(namespace, key string) string {
	return f.prefix + namespace + ":" + key
}

func (f *fakeRedis) GetKey(namespace, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return "", newGuardRedisError("Redis operation failed")
	}
	entry, ok := f.data[f.full(namespace, key)]
	if !ok || time.Now().After(entry.expiry) {
		return "", nil
	}
	return entry.value, nil
}

func (f *fakeRedis) SetKey(namespace, key, value string, ttlSeconds *int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return newGuardRedisError("Redis operation failed")
	}
	expiry := time.Now().Add(time.Duration(1<<62) / 2)
	if ttlSeconds != nil && *ttlSeconds > 0 {
		expiry = time.Now().Add(time.Duration(*ttlSeconds) * time.Second)
	}
	f.data[f.full(namespace, key)] = fakeEntry{value: value, expiry: expiry}
	return nil
}

func (f *fakeRedis) Delete(namespace, key string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return 0, newGuardRedisError("Redis operation failed")
	}
	full := f.full(namespace, key)
	_, ok := f.data[full]
	delete(f.data, full)
	if ok {
		return 1, nil
	}
	return 0, nil
}

func (f *fakeRedis) Keys(pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	suffix := strings.TrimSuffix(pattern, "*")
	for k := range f.data {
		if strings.HasPrefix(k, f.prefix+suffix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeRedis) DeletePattern(pattern string) (int64, error) {
	keys, _ := f.Keys(pattern)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range keys {
		delete(f.data, k)
	}
	return int64(len(keys)), nil
}

func (f *fakeRedis) ScanMatch(pattern string) ([]string, error) {
	return f.Keys(strings.TrimPrefix(pattern, f.prefix))
}

func (f *fakeRedis) PTTL(key string) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.data[key]
	if !ok {
		return -2 * time.Millisecond, nil
	}
	remaining := time.Until(entry.expiry)
	if remaining < 0 {
		remaining = -1 * time.Millisecond
	}
	return remaining, nil
}

func (f *fakeRedis) SetPX(key, value string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = fakeEntry{value: value, expiry: time.Now().Add(ttl)}
	return nil
}

func (f *fakeRedis) DeleteKeys(keys ...string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, k := range keys {
		if _, ok := f.data[k]; ok {
			n++
		}
		delete(f.data, k)
	}
	return n, nil
}

func (f *fakeRedis) BanKey(ip string) string {
	return f.full("banned_ips", ip)
}

func TestBanExactIPWritesFloatStringExpiry(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	ok, err := mgr.Ban("1.2.3.4", 60, "test")
	if err != nil || !ok {
		t.Fatalf("Ban failed: ok=%v err=%v", ok, err)
	}
	value, err := store.GetKey("banned_ips", "1.2.3.4")
	if err != nil {
		t.Fatal(err)
	}
	expiry, err := strconv.ParseFloat(value, 64)
	if err != nil {
		t.Fatalf("expiry %q is not a decimal float string", value)
	}
	now := float64(time.Now().UnixNano()) / 1e9
	if expiry <= now || expiry > now+120 {
		t.Errorf("expiry %v not in (now, now+duration]", expiry)
	}
	if strings.ContainsAny(value, "eE") {
		t.Errorf("expiry %q must be plain decimal like Python str(float)", value)
	}
}

func TestBanRejectsNonPositiveDuration(t *testing.T) {
	mgr := NewIPBanManager(newFakeRedis(), nil)
	if _, err := mgr.Ban("1.2.3.4", 0, "test"); err == nil {
		t.Error("expected error for zero duration")
	}
	if _, err := mgr.Ban("1.2.3.4", -5, "test"); err == nil {
		t.Error("expected error for negative duration")
	}
}

func TestBanCanonicalizesKey(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	if _, err := mgr.Ban("[::FFFF:192.168.1.1]", 60, "test"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.data[store.BanKey("192.168.1.1")]; !ok {
		t.Error("ban not stored under canonical IPv4 key")
	}
}

func TestSelfDoSRefusal(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, []string{"10.0.0.0/8"})
	ok, err := mgr.Ban("127.0.0.1", 60, "test")
	if err != nil || ok {
		t.Errorf("loopback ban must be refused, ok=%v err=%v", ok, err)
	}
	ok, err = mgr.Ban("::1", 60, "test")
	if err != nil || ok {
		t.Errorf("::1 ban must be refused, ok=%v err=%v", ok, err)
	}
	ok, err = mgr.Ban("10.1.2.3", 60, "test")
	if err != nil || ok {
		t.Errorf("trusted-proxy ban must be refused, ok=%v err=%v", ok, err)
	}
	if ok, err := mgr.Ban("10.1.2.3/24", 60, "test"); err != nil || ok {
		t.Errorf("trusted-proxy CIDR ban must be refused, ok=%v err=%v", ok, err)
	}
	ok, err = mgr.Ban("::ffff:127.0.0.1", 60, "test")
	if err != nil || ok {
		t.Errorf("canonicalized mapped loopback ban must be refused, ok=%v err=%v", ok, err)
	}
	ok, err = mgr.Ban("8.8.8.8", 60, "test")
	if err != nil || !ok {
		t.Errorf("public ban must succeed, ok=%v err=%v", ok, err)
	}
}

func TestIsIPBannedLookupOrder(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	if mgr.IsIPBanned("4.4.4.4") {
		t.Error("unbanned IP reported banned")
	}
	if _, err := mgr.Ban("4.4.4.4", 60, "test"); err != nil {
		t.Fatal(err)
	}
	if !mgr.IsIPBanned("4.4.4.4") {
		t.Error("banned IP not detected via local cache")
	}
	mgr2 := NewIPBanManager(store, nil)
	if !mgr2.IsIPBanned("4.4.4.4") {
		t.Error("banned IP not detected via Redis exact check")
	}
}

func TestIsIPBannedLocalExpiryPurges(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	mgr.localSet("5.5.5.5", float64(time.Now().Add(-time.Second).UnixNano())/1e9)
	if mgr.IsIPBanned("5.5.5.5") {
		t.Error("expired local entry must not report banned")
	}
	mgr.mu.Lock()
	_, exists := mgr.bannedIPs["5.5.5.5"]
	mgr.mu.Unlock()
	if exists {
		t.Error("expired local entry not purged")
	}
}

func TestIsIPBannedRedisStaleEarlyDelete(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	now := float64(time.Now().UnixNano()) / 1e9
	if err := store.SetKey("banned_ips", "6.6.6.6", formatExpiry(now-10), intPtr(60)); err != nil {
		t.Fatal(err)
	}
	if mgr.IsIPBanned("6.6.6.6") {
		t.Error("stale Redis ban must not report banned")
	}
	if _, ok := store.data[store.BanKey("6.6.6.6")]; ok {
		t.Error("stale Redis ban key not deleted early")
	}
}

func TestUnban(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	if _, err := mgr.Ban("7.7.7.7", 60, "test"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Unban("7.7.7.7"); err != nil {
		t.Fatal(err)
	}
	if mgr.IsIPBanned("7.7.7.7") {
		t.Error("unbanned IP still banned")
	}
	if _, ok := store.data[store.BanKey("7.7.7.7")]; ok {
		t.Error("Redis key not deleted on unban")
	}
}

func TestUnbanDoesNotRemoveCIDRBan(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	store.fail = true
	if _, err := mgr.Ban("10.9.0.0/24", 60, "test"); err != nil {
		t.Fatal(err)
	}
	_ = mgr.Unban("10.9.0.7")
	if !mgr.IsIPBanned("10.9.0.7") {
		t.Error("CIDR ban must survive unban of member IP")
	}
}

func TestBanNetworksCanonicalCIDRKeys(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	if _, err := mgr.Ban("10.0.0.77/24", 60, "test"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.data[store.full("banned_networks", "10.0.0.0/24")]; !ok {
		t.Error("CIDR ban key must be host-bits-cleared canonical form")
	}
	for k := range store.data {
		if strings.HasPrefix(k, store.prefix+"banned_networks:") && k != store.prefix+"banned_networks:10.0.0.0/24" {
			t.Errorf("unexpected network key %s", k)
		}
	}
}

func TestBanNetworksLocalOnlyOnRedisFailure(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	store.fail = true
	if _, err := mgr.Ban("10.1.0.0/24", 7200, "test"); err != nil {
		t.Fatal(err)
	}
	if mgr.BannedNetworkCount() != 1 {
		t.Error("CIDR ban not stored locally on Redis failure")
	}
	if !mgr.IsIPBanned("10.1.0.5") {
		t.Error("local CIDR ban not enforced")
	}
}

func TestLocalCapClampWhenRedisDown(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	store.fail = true
	if _, err := mgr.Ban("8.8.8.8", 7200, "test"); err != nil {
		t.Fatal(err)
	}
	if !mgr.IsIPBanned("8.8.8.8") {
		t.Error("clamped local ban not enforced")
	}
	mgr.mu.Lock()
	entry := mgr.bannedIPs["8.8.8.8"]
	mgr.mu.Unlock()
	if entry.expiry > float64(time.Now().Add(3600*time.Second).UnixNano())/1e9 {
		t.Errorf("local ban expiry %v exceeds clamped 3600s window", entry.expiry)
	}
}

func TestBanWithoutRedisLocalOnlyClamped(t *testing.T) {
	mgr := NewIPBanManager(nil, nil)
	if _, err := mgr.Ban("9.9.9.9", 7200, "test"); err != nil {
		t.Fatal(err)
	}
	if !mgr.IsIPBanned("9.9.9.9") {
		t.Error("local-only ban not enforced")
	}
	mgr.mu.Lock()
	entry, exists := mgr.bannedIPs["9.9.9.9"]
	mgr.mu.Unlock()
	if !exists {
		t.Fatal("local entry missing")
	}
	if entry.expiry > float64(time.Now().Add(3600*time.Second).UnixNano())/1e9 {
		t.Errorf("local-only ban expiry %v exceeds 3600s clamp", entry.expiry)
	}
}

func TestInvalidBanTargets(t *testing.T) {
	mgr := NewIPBanManager(newFakeRedis(), nil)
	if _, err := mgr.Ban("not-an-ip", 60, "test"); err == nil {
		t.Error("invalid exact IP must error")
	}
	if _, err := mgr.Ban("10.0.0.0/99", 60, "test"); err == nil {
		t.Error("invalid CIDR must error")
	}
}

func TestReset(t *testing.T) {
	store := newFakeRedis()
	mgr := NewIPBanManager(store, nil)
	if _, err := mgr.Ban("1.1.1.1", 60, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Ban("2.2.2.2", 60, "test"); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reset(); err != nil {
		t.Fatal(err)
	}
	if mgr.BannedIPCount() != 0 {
		t.Error("local cache not cleared on reset")
	}
	keys, _ := store.Keys("banned_ips:*")
	if len(keys) != 0 {
		t.Errorf("Redis keys not cleared on reset: %v", keys)
	}
}

func TestMigrationLegacyKeys(t *testing.T) {
	store := newFakeRedis()
	now := time.Now()
	store.data[store.BanKey("[2001:db8::1]")] = fakeEntry{value: "123.456", expiry: now.Add(60 * time.Second)}
	store.data[store.BanKey("[9.8.7.6]")] = fakeEntry{value: "123.456", expiry: now.Add(6000 * time.Second)}
	store.data[store.BanKey("9.8.7.6")] = fakeEntry{value: "123.456", expiry: now.Add(60 * time.Second)}
	store.data[store.BanKey("[8.8.4.4]")] = fakeEntry{value: "123.456", expiry: now.Add(-time.Second)}
	store.data[store.BanKey("9.9.9.9")] = fakeEntry{value: "123.456", expiry: now.Add(6000 * time.Second)}
	store.data[store.full("banned_ips", "8.8.8.8")] = fakeEntry{value: "123.456", expiry: now.Add(60 * time.Second)}

	mgr := NewIPBanManager(store, nil)
	mgr.InitializeRedis(store)

	if _, ok := store.data[store.BanKey("[2001:db8::1]")]; ok {
		t.Error("legacy bracketed key not deleted")
	}
	if _, ok := store.data[store.BanKey("2001:db8::1")]; !ok {
		t.Error("canonical key not written for bracketed legacy key")
	}
	if _, ok := store.data[store.BanKey("[8.8.4.4]")]; ok {
		t.Error("expired legacy key not deleted")
	}
	kept, ok := store.data[store.BanKey("9.9.9.9")]
	if !ok {
		t.Fatal("already-canonical key must be left untouched")
	}
	if time.Until(kept.expiry) < 5900*time.Second {
		t.Error("already-canonical key TTL must be preserved")
	}
	merged, ok := store.data[store.BanKey("9.8.7.6")]
	if !ok {
		t.Fatal("canonical key deleted during merge")
	}
	if time.Until(merged.expiry) < 3000*time.Second {
		t.Error("canonical key must keep the longer legacy expiry")
	}
	if _, ok := store.data[store.BanKey("[9.8.7.6]")]; ok {
		t.Error("legacy key not deleted after merge")
	}
}

func TestKeySchemaByteExact(t *testing.T) {
	store := newFakeRedis()
	if store.full("banned_ips", "1.2.3.4") != "guard_core:banned_ips:1.2.3.4" {
		t.Error("banned_ips key schema mismatch")
	}
	if store.full("banned_networks", "10.0.0.0/24") != "guard_core:banned_networks:10.0.0.0/24" {
		t.Error("banned_networks key schema mismatch")
	}
}

func intPtr(n int) *int {
	return &n
}
