//go:build interop

package guardcore

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	interopPrefix          = "guard_core_interop:"
	interopRateWindow      = 120
	interopRateLimitLoose  = 10000
	interopBanDuration     = 900
	interopLegacyDuration  = 600
	interopCloudTTL        = 3600
	interopPyBanIP         = "203.0.113.7"
	interopPyMappedSpell   = "::ffff:203.0.113.7"
	interopNetworkBan      = "198.51.100.0/24"
	interopNetworkProbe    = "198.51.100.55"
	interopLegacyMappedIP  = "::ffff:203.0.113.9"
	interopLegacyCanonical = "203.0.113.9"
	interopGoBanIP         = "192.0.2.66"
	interopBucketA         = "192.0.2.10"
	interopBucketB         = "192.0.2.11"
	interopGCPEntry        = "192.0.2.128/25"
	interopGCPProbe        = "192.0.2.200"
	interopAWSPayload      = `["203.0.113.0/25|us-east-1", "203.0.113.128/25"]`
)

type interopCheck struct {
	Scenario  string `json:"scenario"`
	Direction string `json:"direction"`
	Name      string `json:"name"`
	Passed    bool   `json:"passed"`
	Detail    string `json:"detail"`
}

type interopReport struct {
	Participant string            `json:"participant"`
	Phase       string            `json:"phase"`
	Passed      int               `json:"passed"`
	Failed      int               `json:"failed"`
	Checks      []interopCheck    `json:"checks"`
	Artifacts   map[string]string `json:"artifacts"`
}

type interopRunner struct {
	t      *testing.T
	report *interopReport
}

func (r *interopRunner) check(scenario, direction, name string, ok bool, detail string) {
	verdict := "ok"
	if !ok {
		verdict = "FAIL"
	}
	line := fmt.Sprintf("%s - [%s] %s", verdict, scenario, name)
	if detail != "" {
		line += fmt.Sprintf(" (%s)", detail)
	}
	fmt.Println(line)
	if ok {
		r.report.Passed++
	} else {
		r.report.Failed++
	}
	r.report.Checks = append(r.report.Checks, interopCheck{
		Scenario: scenario, Direction: direction, Name: name, Passed: ok, Detail: detail,
	})
}

func (r *interopRunner) artifact(key, value string) {
	r.report.Artifacts[key] = value
}

func (r *interopRunner) inputString(input map[string]any, key string) string {
	value, _ := input[key].(string)
	return value
}

func (r *interopRunner) inputInt(input map[string]any, key string) int {
	value, _ := input[key].(float64)
	return int(value)
}

func interopRateConfig(limit int) RateLimitConfig {
	return RateLimitConfig{
		EnableRateLimiting:     true,
		RateLimit:              limit,
		RateLimitWindow:        interopRateWindow,
		EndpointRateLimits:     map[string]RateLimitEntry{},
		EnableRateLimitAutoBan: false,
		EnableIPBanning:        false,
		PassiveMode:            false,
		AutoBanThreshold:       DefaultAutoBanThreshold,
		AutoBanDuration:        DefaultAutoBanDuration,
		ThreatBanConfig:        map[string]ThreatBanEntry{},
		RedisFailOpen:          false,
	}
}

func TestInteropRunner(t *testing.T) {
	phase := os.Getenv("INTEROP_PHASE")
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Fatal("REDIS_HOST not set")
	}
	input := map[string]any{}
	if raw := os.Getenv("INTEROP_INPUT"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			t.Fatalf("INTEROP_INPUT is not valid JSON: %v", err)
		}
	}

	redis := NewRedisManager(RedisConfig{URL: "redis://" + host + ":6379", Prefix: interopPrefix, EnableRedis: true})
	if err := redis.Initialize(); err != nil {
		t.Fatalf("redis initialize failed: %v", err)
	}
	defer func() { _ = redis.Close() }()

	ban := NewIPBanManager(redis, nil)
	if err := ban.InitializeRedis(redis); err != nil {
		t.Fatalf("ip ban initialize failed: %v", err)
	}
	rl := NewRateLimitManager(interopRateConfig(interopRateLimitLoose), redis, ban)
	rl.InitializeRedis(redis)
	rlTight := NewRateLimitManager(interopRateConfig(1), redis, ban)
	rlTight.InitializeRedis(redis)

	runner := &interopRunner{t: t, report: &interopReport{
		Participant: "go", Phase: phase, Checks: []interopCheck{}, Artifacts: map[string]string{},
	}}

	switch phase {
	case "go_read_then_write":
		runGoReadThenWrite(runner, redis, ban, rl, rlTight, input)
	default:
		t.Fatalf("go runner does not serve phase %q", phase)
	}

	if reportFile := os.Getenv("INTEROP_REPORT_FILE"); reportFile != "" {
		data, err := json.MarshalIndent(runner.report, "", "  ")
		if err != nil {
			t.Fatalf("report marshal failed: %v", err)
		}
		if err := os.WriteFile(reportFile, data, 0o644); err != nil {
			t.Fatalf("report write failed: %v", err)
		}
	}
	total := runner.report.Passed + runner.report.Failed
	t.Logf("Passed: %d, Failed: %d", runner.report.Passed, runner.report.Failed)
	if runner.report.Failed > 0 {
		t.Fatalf("interop phase %q RED: %d/%d checks failed", phase, runner.report.Failed, total)
	}
}

func runGoReadThenWrite(r *interopRunner, redis *RedisManager, ban *IPBanManager, rl, rlTight *RateLimitManager, input map[string]any) {
	pyBanned := ban.IsIPBanned(interopPyBanIP)
	r.check("exact_ban_read", "py:go", "go honors the python ban 203.0.113.7", pyBanned, fmt.Sprintf("IsIPBanned=%v", pyBanned))

	mappedBanned := ban.IsIPBanned(interopPyMappedSpell)
	r.check("canonical_mapped_spelling", "py:go", "go maps ::ffff:203.0.113.7 onto the canonical ban", mappedBanned, fmt.Sprintf("IsIPBanned=%v", mappedBanned))

	pyRaw, _ := redis.GetKey("banned_ips", interopPyBanIP)
	pyExpiry, parseErr := strconv.ParseFloat(pyRaw, 64)
	now := float64(time.Now().UnixNano()) / 1e9
	wantRaw := r.inputString(input, "py_ban_expiry_raw")
	r.check("float_string_value", "py:go", "python ban expiry is byte-equal and parses",
		pyRaw == wantRaw && parseErr == nil && pyExpiry > now, fmt.Sprintf("raw=%q", pyRaw))

	netRaw, _ := redis.GetKey("banned_networks", interopNetworkBan)
	netExpiry, netParseErr := strconv.ParseFloat(netRaw, 64)
	prefix, prefixErr := netip.ParsePrefix(interopNetworkBan)
	contains := prefixErr == nil && prefix.Contains(netip.MustParseAddr(interopNetworkProbe))
	r.check("network_ban_wire", "py:go", "banned_networks key carries a float expiry and contains the probe IP",
		netParseErr == nil && netExpiry > now && contains, fmt.Sprintf("raw=%q", netRaw))
	managerSeesNetwork := ban.IsIPBanned(interopNetworkProbe)
	r.check("network_ban_no_redis_reader", "py:go", "go manager does not read banned_networks from redis (normative local-only CIDR)",
		!managerSeesNetwork, fmt.Sprintf("IsIPBanned(%s)=%v", interopNetworkProbe, managerSeesNetwork))

	legacyKeys, _ := redis.ScanMatch(interopPrefix + "banned_ips:*")
	allCanonical := true
	for _, key := range legacyKeys {
		rawIP := strings.TrimPrefix(key, interopPrefix+"banned_ips:")
		if CanonicalizeIP(rawIP) != rawIP {
			allCanonical = false
		}
	}
	r.check("legacy_migration_keys", "py:go", "migration leaves only canonical banned_ips keys", allCanonical,
		fmt.Sprintf("keys=%v", legacyKeys))

	legacyRaw, _ := redis.GetKey("banned_ips", interopLegacyCanonical)
	r.check("legacy_migration_value", "py:go", "migrated canonical key keeps the python-written value byte-exact",
		legacyRaw == r.inputString(input, "legacy_value_raw"), fmt.Sprintf("raw=%q", legacyRaw))

	legacyPTTL, _ := redis.PTTL(interopPrefix + "banned_ips:" + interopLegacyCanonical)
	r.check("legacy_migration_ttl", "py:go", "migrated canonical ban kept a positive TTL within the legacy bound",
		legacyPTTL > 0 && legacyPTTL <= interopLegacyDuration*time.Second, fmt.Sprintf("pttl=%v", legacyPTTL))

	legacyGone, _ := redis.ScanMatch(interopPrefix + "banned_ips:" + interopLegacyMappedIP)
	r.check("legacy_migration_keys", "py:go", "legacy mapped-form key is deleted after migration", len(legacyGone) == 0,
		fmt.Sprintf("leftover=%v", legacyGone))

	legacyBanned := ban.IsIPBanned(interopLegacyCanonical)
	legacyMapped := ban.IsIPBanned(interopLegacyMappedIP)
	r.check("legacy_migration_banned", "py:go", "go honors the migrated ban by canonical and mapped spelling",
		legacyBanned && legacyMapped, fmt.Sprintf("canonical=%v mapped=%v", legacyBanned, legacyMapped))

	out, err := rl.CheckRateLimit(interopBucketA, "", nil, nil)
	r.check("rate_continuity", "py:go", "go observes the shared bucket A count",
		err == nil && out != nil && !out.Blocked && out.Count == r.inputInt(input, "expected_a_first"),
		fmt.Sprintf("count=%v", outcomeCount(out, err)))

	crossing, err := rlTight.CheckRateLimit(interopBucketA, "", nil, nil)
	r.check("rate_blocked_crossing", "py+go:go", "bucket A blocks at limit 1 with the exact shared count",
		err == nil && crossing != nil && crossing.Blocked && crossing.Count == r.inputInt(input, "expected_a_crossing"),
		fmt.Sprintf("count=%v", outcomeCount(crossing, err)))

	for i, want := range []int{1, r.inputInt(input, "expected_b_second")} {
		outB, err := rl.CheckRateLimit(interopBucketB, "", nil, nil)
		r.check("rate_write", "go:go", fmt.Sprintf("go writes bucket B hit %d", i+1),
			err == nil && outB != nil && !outB.Blocked && outB.Count == want,
			fmt.Sprintf("count=%v", outcomeCount(outB, err)))
	}

	store := NewRedisCloudIPStore(redis)
	entries, found, err := store.Get("AWS")
	joined := strings.Join(entries, "|")
	r.check("cloud_aws_present", "py:go", "go decodes the python-written AWS cache",
		err == nil && found && joined == "203.0.113.0/25|us-east-1|203.0.113.128/25", fmt.Sprintf("entries=%v", entries))

	awsRaw, _ := redis.GetKey("cloud_ip_v2", "AWS")
	encoded, encErr := encodeCloudIPv2Payload(entries)
	r.check("cloud_payload_bytes", "py:go", "go re-encodes the AWS payload byte-exact",
		encErr == nil && encoded == awsRaw && awsRaw == interopAWSPayload, fmt.Sprintf("raw=%q", awsRaw))

	cloud := NewCloudManager()
	cloud.SetStore(store)
	if err := cloud.RefreshAsync([]string{"AWS"}, interopCloudTTL); err != nil {
		r.check("cloud_refresh", "py:go", "go refreshAsync AWS", false, err.Error())
	}
	r.check("cloud_block", "py:go", "go blocks an AWS IP from the python payload",
		cloud.IsCloudIP("203.0.113.200", []string{"AWS"}), "")
	carved := cloud.IsCloudIP("203.0.113.5", []string{"AWS:!us-east-1"})
	r.check("cloud_carveout", "py:go", "go honors the AWS us-east-1 carve-out",
		!carved && cloud.IsCloudIP("203.0.113.5", []string{"AWS"}), fmt.Sprintf("carved=%v", carved))

	banOK, banErr := ban.Ban(interopGoBanIP, interopBanDuration, "interop_go")
	r.check("exact_ban_write", "go:go", "go bans 192.0.2.66", banErr == nil && banOK, fmt.Sprintf("err=%v", banErr))
	goRaw, _ := redis.GetKey("banned_ips", interopGoBanIP)
	goExpiry, goParseErr := strconv.ParseFloat(goRaw, 64)
	now = float64(time.Now().UnixNano()) / 1e9
	r.check("float_string_value", "go:go", "go ban expiry is a shortest round-trip float in the future",
		goParseErr == nil && goExpiry > now && goRaw == formatExpiry(goExpiry), fmt.Sprintf("raw=%q", goRaw))
	r.artifact("go_ban_expiry_raw", goRaw)

	if err := store.Set("GCP", []string{interopGCPEntry}, interopCloudTTL); err != nil {
		r.check("cloud_gcp_write", "go:go", "go writes cloud_ip_v2:GCP", false, err.Error())
	} else {
		r.check("cloud_gcp_write", "go:go", "go writes cloud_ip_v2:GCP", true, "")
	}
	gcpRaw, _ := redis.GetKey("cloud_ip_v2", "GCP")
	gcpEncoded, gcpEncErr := encodeCloudIPv2Payload([]string{interopGCPEntry})
	r.check("cloud_payload_bytes", "go:go", "go GCP payload matches its own python-format encoder",
		gcpEncErr == nil && gcpRaw == gcpEncoded, fmt.Sprintf("raw=%q", gcpRaw))
	r.artifact("gcp_payload_raw", gcpRaw)

	if err := cloud.RefreshAsync([]string{"GCP"}, interopCloudTTL); err != nil {
		r.check("cloud_refresh", "go:go", "go refreshAsync GCP", false, err.Error())
	}
	r.check("cloud_block", "go:go", "go blocks a GCP IP from its own payload",
		cloud.IsCloudIP(interopGCPProbe, []string{"GCP"}), "")

	bucketPTTL, _ := redis.PTTL(rateLimitRedisKey(interopPrefix, interopBucketA, ""))
	r.check("ttl_semantics", "py:go", "bucket A TTL stays within 2x the window",
		bucketPTTL > 0 && bucketPTTL <= time.Duration(interopRateWindow*2)*time.Second, fmt.Sprintf("pttl=%v", bucketPTTL))
}

func outcomeCount(out *RateLimitOutcome, err error) string {
	if err != nil {
		return "error"
	}
	if out == nil {
		return "nil"
	}
	return strconv.Itoa(out.Count)
}
