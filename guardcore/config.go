package guardcore

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

type UnsupportedFeatureError struct {
	Feature string
	Reason  string
}

func (e *UnsupportedFeatureError) Error() string {
	return fmt.Sprintf("unsupported feature %q enabled: %s (fail-closed per conformance.md)", e.Feature, e.Reason)
}

const (
	DefaultRedisPrefix        = "guard_core:"
	DefaultRedisURL           = "redis://localhost:6379"
	DefaultTrustedProxyDepth  = 1
	UnknownClientIdentity     = "unknown"
	BlockedStatusSecurityFail = 500
)

var AllDetectionCategories = []string{
	"xss", "sqli", "dir_traversal", "path_traversal", "cmd_injection",
	"file_inclusion", "ldap", "xml", "ssrf", "nosql", "file_upload",
	"template", "http_split", "sensitive_file", "cms_probing", "recon",
	"proto_pollution", "code_injection", "deserialization",
}

var ValidThreatBanCategories = func() map[string]bool {
	m := map[string]bool{"rate_limit": true}
	for _, c := range AllDetectionCategories {
		m[c] = true
	}
	return m
}()

var DefaultExcludePaths = []string{
	"/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static",
}

var CheckNameValues = []string{
	"route_config", "emergency_mode", "https_enforcement", "request_logging",
	"request_size_content", "required_headers", "authentication", "referrer",
	"custom_validators", "time_window", "cloud_ip_refresh", "ip_security",
	"cloud_provider", "user_agent", "rate_limit", "suspicious_activity",
	"custom_request",
}

var ValidBypassChecks = map[string]bool{
	"all": true, "ip_ban": true, "ip": true, "clouds": true,
	"rate_limit": true, "penetration": true,
}

var ValidLogLevels = map[string]bool{
	"INFO": true, "DEBUG": true, "WARNING": true, "ERROR": true, "CRITICAL": true,
}

type SecurityConfig struct {
	TrustedProxies       []string
	TrustedProxyDepth    int
	TrustXForwardedProto bool
	Whitelist            []string
	Blacklist            []string

	EnableRedis   bool
	RedisURL      string
	RedisPrefix   string
	RedisFailOpen bool

	EnableIPBanning        bool
	AutoBanThreshold       int
	AutoBanDuration        int
	ThreatBanConfig        map[string]ThreatBanEntry
	EnableRateLimitAutoBan bool

	EnableRateLimiting bool
	RateLimit          int
	RateLimitWindow    int
	EndpointRateLimits map[string]RateLimitEntry

	EnablePenetrationDetection  bool
	EnabledDetectionCategories  []string
	ExcludedDetectionHeaders    map[string]bool
	ExcludedDetectionParams     map[string]bool
	ExcludedDetectionBodyFields map[string]bool
	Detection                   Config

	PassiveMode           bool
	FailSecure            bool
	RouteResolutionStrict bool
	ExcludePaths          []string
	CustomErrorResponses  map[int]string

	OnBlock func(req Request, payload map[string]any)

	MutedCheckLogs         map[string]bool
	LogSensitiveHeaders    map[string]bool
	LogSensitiveParams     map[string]bool
	LogSensitiveBodyFields map[string]bool

	EnforceHTTPS        bool
	EmergencyMode       bool
	EmergencyWhitelist  []string
	AuthVerifier        AuthVerifier
	EnableDynamicRules  bool
	EnableAgent         bool
	EnableCORS          bool
	BlockCloudProviders []string
	BlockedUserAgents   []string
	WhitelistCountries  []string
	BlockedCountries    []string
	GlobalBehaviorRules []string
	CustomRequestCheck  func(req Request) *Response
	LogRequestLevel     string

	revision atomic.Uint64
}

func DefaultSecurityConfig() *SecurityConfig {
	categories := make([]string, len(AllDetectionCategories))
	copy(categories, AllDetectionCategories)
	return &SecurityConfig{
		TrustedProxyDepth:           DefaultTrustedProxyDepth,
		EnableRedis:                 true,
		RedisURL:                    DefaultRedisURL,
		RedisPrefix:                 DefaultRedisPrefix,
		EnableIPBanning:             true,
		AutoBanThreshold:            DefaultAutoBanThreshold,
		AutoBanDuration:             DefaultAutoBanDuration,
		ThreatBanConfig:             map[string]ThreatBanEntry{},
		EnableRateLimiting:          true,
		RateLimit:                   DefaultRateLimit,
		RateLimitWindow:             DefaultRateLimitWindow,
		EndpointRateLimits:          map[string]RateLimitEntry{},
		EnablePenetrationDetection:  true,
		EnabledDetectionCategories:  categories,
		ExcludedDetectionHeaders:    map[string]bool{},
		ExcludedDetectionParams:     map[string]bool{},
		ExcludedDetectionBodyFields: map[string]bool{},
		Detection:                   DefaultConfig(),
		FailSecure:                  true,
		ExcludePaths:                append([]string(nil), DefaultExcludePaths...),
		CustomErrorResponses:        map[int]string{},
		MutedCheckLogs:              map[string]bool{},
		LogSensitiveHeaders:         map[string]bool{},
		LogSensitiveParams:          map[string]bool{},
		LogSensitiveBodyFields:      map[string]bool{},
	}
}

func NewSecurityConfig(mutate func(*SecurityConfig)) (*SecurityConfig, error) {
	cfg := DefaultSecurityConfig()
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *SecurityConfig) Revision() uint64 { return c.revision.Load() }

func (c *SecurityConfig) BumpRevision() { c.revision.Add(1) }

func (c *SecurityConfig) unsupported(feature, reason string) error {
	return &UnsupportedFeatureError{Feature: feature, Reason: reason}
}

func (c *SecurityConfig) Validate() error {
	if len(c.GlobalBehaviorRules) > 0 {
		return c.unsupported("global_behavior_rules", "behavioral rules are not implemented in this port yet")
	}
	if c.CustomRequestCheck != nil {
		return c.unsupported("custom_request_check", "custom request checks are not implemented in this port yet")
	}
	if c.EnableDynamicRules {
		return c.unsupported("enable_dynamic_rules", "dynamic rules are not implemented in this port yet")
	}
	if c.EnableAgent {
		return c.unsupported("enable_agent", "Guard Agent telemetry is not implemented in this port yet")
	}
	if c.EnableCORS {
		return c.unsupported("enable_cors", "CORS handling is not implemented in this port yet")
	}
	if len(c.BlockCloudProviders) > 0 {
		return c.unsupported("block_cloud_providers", "cloud provider blocking is not implemented in this port yet")
	}
	if len(c.WhitelistCountries) > 0 {
		return c.unsupported("whitelist_countries", "geo blocking is not implemented in this port yet")
	}
	if len(c.BlockedCountries) > 0 {
		return c.unsupported("blocked_countries", "geo blocking is not implemented in this port yet")
	}
	if c.LogRequestLevel != "" {
		if !ValidLogLevels[strings.ToUpper(c.LogRequestLevel)] {
			return fmt.Errorf("log_request_level: invalid level %q (want INFO/DEBUG/WARNING/ERROR/CRITICAL)", c.LogRequestLevel)
		}
		return c.unsupported("log_request_level", "per-request logging is not implemented in this port yet")
	}

	if c.TrustedProxyDepth < 1 {
		return fmt.Errorf("trusted_proxy_depth: must be >= 1, got %d", c.TrustedProxyDepth)
	}
	for _, pattern := range c.BlockedUserAgents {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("blocked_user_agents: invalid pattern %q: %w", pattern, err)
		}
	}
	if err := validateIPList("trusted_proxies", c.TrustedProxies); err != nil {
		return err
	}
	if err := validateIPList("whitelist", c.Whitelist); err != nil {
		return err
	}
	if err := validateIPList("blacklist", c.Blacklist); err != nil {
		return err
	}
	if c.AutoBanThreshold < 1 {
		return fmt.Errorf("auto_ban_threshold: must be >= 1, got %d", c.AutoBanThreshold)
	}
	if c.AutoBanDuration < 1 {
		return fmt.Errorf("auto_ban_duration: must be >= 1, got %d", c.AutoBanDuration)
	}
	for category, entry := range c.ThreatBanConfig {
		if !ValidThreatBanCategories[category] {
			return fmt.Errorf("threat_ban_config: unknown category %q", category)
		}
		if entry.Threshold < 1 {
			return fmt.Errorf("threat_ban_config[%s]: threshold must be >= 1, got %d", category, entry.Threshold)
		}
		if entry.Duration < 1 {
			return fmt.Errorf("threat_ban_config[%s]: duration must be >= 1, got %d", category, entry.Duration)
		}
	}
	if c.RateLimit < 1 {
		return fmt.Errorf("rate_limit: must be >= 1, got %d", c.RateLimit)
	}
	if c.RateLimitWindow < 1 {
		return fmt.Errorf("rate_limit_window: must be >= 1, got %d", c.RateLimitWindow)
	}
	for endpoint, entry := range c.EndpointRateLimits {
		if entry.Requests < 1 {
			return fmt.Errorf("endpoint_rate_limits[%s]: requests must be >= 1, got %d", endpoint, entry.Requests)
		}
		if entry.Window < 1 {
			return fmt.Errorf("endpoint_rate_limits[%s]: window must be >= 1, got %d", endpoint, entry.Window)
		}
	}
	validCategories := map[string]bool{}
	for _, cat := range AllDetectionCategories {
		validCategories[cat] = true
	}
	for _, cat := range c.EnabledDetectionCategories {
		if !validCategories[cat] {
			return fmt.Errorf("enabled_detection_categories: unknown category %q", cat)
		}
	}
	if c.EnablePenetrationDetection && len(c.EnabledDetectionCategories) == 0 {
		return fmt.Errorf("enabled_detection_categories: detection is enabled but no categories are enabled, so it can never match")
	}
	for name := range c.MutedCheckLogs {
		if !isKnownCheckName(name) {
			return fmt.Errorf("muted_check_logs: unknown check name %q", name)
		}
	}
	for i, entry := range c.ExcludePaths {
		if len(entry) == 0 || entry[0] != '/' {
			return fmt.Errorf("exclude_paths[%d]: %q is not an absolute path", i, entry)
		}
	}
	if c.Detection.CompilerTimeout <= 0 {
		c.Detection.CompilerTimeout = 2 * time.Second
	}
	if c.Detection.MaxContentLength <= 0 {
		c.Detection.MaxContentLength = 10000
	}
	if c.Detection.MaxBodyInspectBytes <= 0 {
		c.Detection.MaxBodyInspectBytes = 262144
	}
	if c.RedisURL == "" {
		c.RedisURL = DefaultRedisURL
	}
	if c.RedisPrefix == "" {
		c.RedisPrefix = DefaultRedisPrefix
	}
	if c.EndpointRateLimits == nil {
		c.EndpointRateLimits = map[string]RateLimitEntry{}
	}
	if c.ThreatBanConfig == nil {
		c.ThreatBanConfig = map[string]ThreatBanEntry{}
	}
	if c.CustomErrorResponses == nil {
		c.CustomErrorResponses = map[int]string{}
	}
	if c.MutedCheckLogs == nil {
		c.MutedCheckLogs = map[string]bool{}
	}
	if c.LogSensitiveHeaders == nil {
		c.LogSensitiveHeaders = map[string]bool{}
	}
	if c.LogSensitiveParams == nil {
		c.LogSensitiveParams = map[string]bool{}
	}
	if c.LogSensitiveBodyFields == nil {
		c.LogSensitiveBodyFields = map[string]bool{}
	}
	return nil
}

func validateIPList(field string, entries []string) error {
	for _, entry := range entries {
		if strings.HasSuffix(entry, "/0") {
			if _, err := netip.ParsePrefix(entry); err != nil {
				return fmt.Errorf("%s: invalid IP or CIDR %q", field, entry)
			}
			continue
		}
		if _, err := netip.ParseAddr(entry); err != nil {
			if _, perr := netip.ParsePrefix(entry); perr != nil {
				return fmt.Errorf("%s: invalid IP or CIDR %q", field, entry)
			}
		}
	}
	return nil
}

func isKnownCheckName(name string) bool {
	for _, known := range CheckNameValues {
		if known == name {
			return true
		}
	}
	return false
}

func canonicalizeIPString(value string) string {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return value
	}
	return addr.String()
}

func ipMatchesList(ip string, entries []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry, "/0") || strings.Contains(entry, "/") {
			prefix, perr := netip.ParsePrefix(entry)
			if perr != nil {
				continue
			}
			if prefix.Contains(addr.Unmap()) || prefix.Contains(addr) {
				return true
			}
			continue
		}
		if canonicalizeIPString(entry) == addr.String() {
			return true
		}
	}
	return false
}

func redactURLForDisplay(path string, query map[string]string, sensitiveParams map[string]bool) string {
	if len(query) == 0 || len(sensitiveParams) == 0 {
		return path
	}
	var b strings.Builder
	b.WriteString(path)
	first := true
	for k, v := range query {
		if first {
			b.WriteByte('?')
			first = false
		} else {
			b.WriteByte('&')
		}
		b.WriteString(urlQueryEscape(k))
		b.WriteByte('=')
		if sensitiveParams[strings.ToLower(k)] {
			b.WriteString("[REDACTED]")
		} else {
			b.WriteString(urlQueryEscape(v))
		}
	}
	return b.String()
}

func urlQueryEscape(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.' || ch == '~' {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}
