package guardcore

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
)

const (
	IPBanBlockedStatus    = 403
	IPBanBlockedMessage   = "IP address banned"
	RestrictionBlockedMsg = "Forbidden"
	SuspiciousBlockedMsg  = "Suspicious activity detected"
	SuspiciousBannedMsg   = "IP has been banned"
)

var onBlockExcludedCheckNames = map[string]bool{
	"custom_request": true, "custom_validators": true, "https_enforcement": true,
}

type SecurityCheck interface {
	CheckName() string
	AppliesTo(cfg *SecurityConfig) bool
	EnforcedOnExcludedPaths() bool
	Check(req Request) *Response
}

type unsupportedCheck struct {
	name     string
	excluded bool
	applies  func(cfg *SecurityConfig) bool
}

func (c *unsupportedCheck) CheckName() string                  { return c.name }
func (c *unsupportedCheck) EnforcedOnExcludedPaths() bool      { return c.excluded }
func (c *unsupportedCheck) AppliesTo(cfg *SecurityConfig) bool { return c.applies(cfg) }
func (c *unsupportedCheck) Check(req Request) *Response {
	panic(&UnsupportedFeatureError{
		Feature: c.name,
		Reason:  "check reached execution although the port does not implement it yet",
	})
}

type ipSecurityCheck struct {
	cfg  *SecurityConfig
	ban  *IPBanManager
	name string
}

func (c *ipSecurityCheck) CheckName() string                  { return c.name }
func (c *ipSecurityCheck) EnforcedOnExcludedPaths() bool      { return true }
func (c *ipSecurityCheck) AppliesTo(cfg *SecurityConfig) bool { return true }

func (c *ipSecurityCheck) Check(req Request) *Response {
	cfg := c.cfg
	state := req.State()
	ip := resolveClientIP(req)
	if ip == "" {
		return nil
	}
	if !state.HasBypass("ip_ban") && c.ban != nil && c.ban.IsIPBanned(ip) {
		reason := fmt.Sprintf("Banned IP attempted access: %s", ip)
		stashBlock(state, reason, "banned_ip")
		if cfg.PassiveMode {
			return nil
		}
		return errorResponse(403, IPBanBlockedMessage)
	}
	if state.ExclusionScoped {
		return c.checkGlobal(req, ip)
	}
	if state.HasBypass("ip") {
		return nil
	}
	return c.checkGlobal(req, ip)
}

func (c *ipSecurityCheck) checkGlobal(req Request, ip string) *Response {
	state := req.State()
	whitelist := c.cfg.Whitelist
	blacklist := c.cfg.Blacklist
	if len(whitelist) > 0 {
		if !ipMatchesList(ip, whitelist) {
			return c.deny(state, ip, "IP not in whitelist")
		}
		state.IsWhitelisted = true
		return nil
	}
	if len(blacklist) > 0 && ipMatchesList(ip, blacklist) {
		return c.deny(state, ip, "IP is blacklisted")
	}
	return nil
}

func (c *ipSecurityCheck) deny(state *RequestState, ip, reason string) *Response {
	stashBlock(state, reason, "ip_restriction")
	if c.cfg.PassiveMode {
		return nil
	}
	return errorResponse(403, RestrictionBlockedMsg)
}

type rateLimitCheck struct {
	cfg     *SecurityConfig
	manager *RateLimitManager
}

func (c *rateLimitCheck) CheckName() string             { return "rate_limit" }
func (c *rateLimitCheck) EnforcedOnExcludedPaths() bool { return true }
func (c *rateLimitCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg.EnableRateLimiting || len(cfg.EndpointRateLimits) > 0
}

func (c *rateLimitCheck) Check(req Request) *Response {
	state := req.State()
	if state.IsWhitelisted || state.HasBypass("rate_limit") {
		return nil
	}
	ip := resolveClientIP(req)
	if ip == "" {
		return nil
	}
	cfg := c.cfg
	outcome, err := c.manager.CheckRateLimit(ip, req.URLPath(), nil, nil)
	if err != nil {
		panic(err)
	}
	if outcome == nil || !outcome.Blocked {
		return nil
	}
	reason := fmt.Sprintf("Rate limit exceeded: %d requests per %d seconds", cfg.RateLimit, cfg.RateLimitWindow)
	stashBlock(state, reason, "rate_limit")
	if cfg.PassiveMode {
		firePassiveBlockHook(cfg, req, "rate_limit", reason, "rate_limit")
		return nil
	}
	return errorResponse(429, "Too many requests")
}

type suspiciousActivityCheck struct {
	cfg    *SecurityConfig
	ban    *IPBanManager
	counts *suspiciousCountStore
}

type suspiciousCountStore struct {
	mu sync.Mutex
	m  map[string]map[string]int
}

func (c *suspiciousActivityCheck) CheckName() string             { return "suspicious_activity" }
func (c *suspiciousActivityCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *suspiciousActivityCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg.EnablePenetrationDetection
}

func (c *suspiciousActivityCheck) Check(req Request) *Response {
	state := req.State()
	if state.IsWhitelisted {
		return nil
	}
	ip := resolveClientIP(req)
	if ip == "" {
		return nil
	}
	cfg := c.cfg
	if state.HasBypass("penetration") {
		return nil
	}
	categories, reason := detectThreat(req, cfg)
	if len(categories) == 0 {
		return nil
	}
	stashBlock(state, reason, strings.Join(categories, ","))
	if cfg.PassiveMode {
		firePassiveBlockHook(cfg, req, "suspicious_activity", reason, strings.Join(categories, ","))
		return nil
	}
	if applied := c.registerViolations(cfg, ip, categories); applied {
		return errorResponse(403, SuspiciousBannedMsg)
	}
	return errorResponse(400, SuspiciousBlockedMsg)
}

func (c *suspiciousActivityCheck) registerViolations(cfg *SecurityConfig, ip string, categories []string) bool {
	c.counts.mu.Lock()
	perIP := c.counts.m[ip]
	if perIP == nil {
		perIP = map[string]int{}
		c.counts.m[ip] = perIP
	}
	for _, category := range categories {
		perIP[category]++
	}
	categoriesCopy := make(map[string]int, len(perIP))
	for k, v := range perIP {
		categoriesCopy[k] = v
	}
	c.counts.mu.Unlock()

	if !cfg.EnableIPBanning || c.ban == nil {
		return false
	}
	for _, category := range categories {
		threshold := cfg.AutoBanThreshold
		duration := cfg.AutoBanDuration
		if entry, ok := cfg.ThreatBanConfig[category]; ok {
			threshold = entry.Threshold
			duration = entry.Duration
		}
		c.counts.mu.Lock()
		count := c.counts.m[ip][category]
		c.counts.mu.Unlock()
		if count < threshold {
			continue
		}
		applied, err := c.ban.Ban(ip, duration, "penetration:"+category)
		if err != nil || !applied {
			continue
		}
		return true
	}
	return false
}

func detectThreat(req Request, cfg *SecurityConfig) ([]string, string) {
	enabled := map[string]bool{}
	for _, category := range cfg.EnabledDetectionCategories {
		enabled[category] = true
	}
	type value struct {
		content string
		context string
	}
	var values []value
	if path := req.URLPath(); path != "" {
		values = append(values, value{path, "url_path"})
	}
	for key, v := range req.QueryParams() {
		if cfg.ExcludedDetectionParams[strings.ToLower(key)] {
			continue
		}
		values = append(values, value{v, "query_param"})
	}
	headers := req.Headers()
	for name := range headers.Map() {
		if cfg.ExcludedDetectionHeaders[strings.ToLower(name)] {
			continue
		}
		if hv, ok := headers.Get(name); ok && hv != "" {
			values = append(values, value{hv, "header"})
		}
	}
	var keys []string
	_ = keys
	for _, v := range values {
		result := Detect(v.content, resolveClientIP(req), v.context)
		if !result.IsThreat {
			continue
		}
		var categories []string
		seen := map[string]bool{}
		for _, threat := range result.Threats {
			category, _ := threat["category"].(string)
			if category == "" || !enabled[category] || seen[category] {
				continue
			}
			seen[category] = true
			categories = append(categories, category)
		}
		if len(categories) == 0 {
			return nil, ""
		}
		sort.Strings(categories)
		return categories, fmt.Sprintf("Penetration patterns detected: %s", strings.Join(categories, ", "))
	}
	return nil, ""
}

func stashBlock(state *RequestState, reason, triggerInfo string) {
	state.BlockStash = &BlockStash{Reason: reason, TriggerInfo: triggerInfo}
}

func errorResponse(statusCode int, message string) *Response {
	factory := NewResponseFactory()
	return factory.CreateResponse(message, statusCode)
}

func resolveClientIP(req Request) string {
	state := req.State()
	if state.ClientIP != "" {
		return canonicalizeIPString(state.ClientIP)
	}
	if host := req.ClientHost(); host != "" {
		return canonicalizeIPString(host)
	}
	return ""
}

func firePassiveBlockHook(cfg *SecurityConfig, req Request, checkName, reason, triggerInfo string) {
	fireBlockHook(cfg, req, checkName, reason, triggerInfo, true, 0)
}

func fireBlockHook(cfg *SecurityConfig, req Request, checkName, reason, triggerInfo string, passiveMode bool, statusCode int) {
	if cfg == nil || cfg.OnBlock == nil || onBlockExcludedCheckNames[checkName] {
		return
	}
	ip := resolveClientIP(req)
	if ip == "" {
		ip = UnknownClientIdentity
	}
	payload := map[string]any{
		"check_name":   checkName,
		"reason":       reason,
		"trigger_info": triggerInfo,
		"passive_mode": passiveMode,
		"client_ip":    ip,
		"path":         req.URLPath(),
		"method":       req.Method(),
		"status_code":  statusCode,
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("on_block hook raised: %v", r)
			}
		}()
		cfg.OnBlock(req, payload)
	}()
}

type SecurityCheckPipeline struct {
	mu                     sync.RWMutex
	checks                 []SecurityCheck
	config                 *SecurityConfig
	rebuildChecks          func() []SecurityCheck
	watchedContainerFields []string
	mutedCheckLogs         map[string]bool
	builtRevision          uint64
	builtSignature         []int
	logger                 *log.Logger
}

var watchedContainerFields = []string{"block_cloud_providers", "blocked_user_agents", "endpoint_rate_limits"}

func NewSecurityCheckPipeline(checks []SecurityCheck, cfg *SecurityConfig, rebuild func() []SecurityCheck) *SecurityCheckPipeline {
	p := &SecurityCheckPipeline{
		checks:                 checks,
		config:                 cfg,
		rebuildChecks:          rebuild,
		watchedContainerFields: watchedContainerFields,
		mutedCheckLogs:         map[string]bool{},
		logger:                 log.Default(),
	}
	if cfg != nil {
		p.builtRevision = cfg.Revision()
		p.builtSignature = p.containerSignature(cfg)
		for name := range cfg.MutedCheckLogs {
			p.mutedCheckLogs[name] = true
		}
	}
	return p
}

func (p *SecurityCheckPipeline) containerSignature(cfg *SecurityConfig) []int {
	sig := make([]int, len(p.watchedContainerFields))
	for i, field := range p.watchedContainerFields {
		switch field {
		case "block_cloud_providers":
			sig[i] = len(cfg.BlockCloudProviders)
		case "blocked_user_agents":
			sig[i] = len(cfg.BlockedUserAgents)
		case "endpoint_rate_limits":
			sig[i] = len(cfg.EndpointRateLimits)
		}
	}
	return sig
}

func (p *SecurityCheckPipeline) isStale() bool {
	if p.config == nil || p.rebuildChecks == nil {
		return false
	}
	if p.config.Revision() != p.builtRevision {
		return true
	}
	current := p.containerSignature(p.config)
	for i := range current {
		if current[i] != p.builtSignature[i] {
			return true
		}
	}
	return false
}

func (p *SecurityCheckPipeline) rebuildIfStale() error {
	p.mu.Lock()
	stale := p.isStale()
	p.mu.Unlock()
	if !stale {
		return nil
	}
	cfg := p.config
	revision := cfg.Revision()
	signature := p.containerSignature(cfg)
	muted := map[string]bool{}
	for name := range cfg.MutedCheckLogs {
		muted[name] = true
	}
	checks := p.rebuildChecks()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checks = checks
	p.mutedCheckLogs = muted
	p.builtRevision = revision
	p.builtSignature = signature
	return nil
}

func (p *SecurityCheckPipeline) CheckNames() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, len(p.checks))
	for i, c := range p.checks {
		names[i] = c.CheckName()
	}
	return names
}

func (p *SecurityCheckPipeline) Execute(req Request) *Response {
	if err := p.rebuildIfStale(); err != nil {
		return p.handleRebuildError(req, err)
	}
	exclusionScoped := req.State().ExclusionScoped
	p.mu.RLock()
	checks := p.checks
	muted := p.mutedCheckLogs
	p.mu.RUnlock()

	for _, check := range checks {
		if exclusionScoped && !check.EnforcedOnExcludedPaths() {
			continue
		}
		resp, err := runCheck(check, req)
		if err != nil {
			if errorResponse := p.handleCheckError(check, req, err, muted); errorResponse != nil {
				return errorResponse
			}
			continue
		}
		if resp == nil {
			continue
		}
		if !muted[check.CheckName()] {
			p.logger.Printf("Request blocked by %s (path=%s method=%s)", check.CheckName(), req.URLPath(), req.Method())
		}
		cfg := p.config
		var reason, triggerInfo string
		if stash := req.State().BlockStash; stash != nil {
			reason = stash.Reason
			triggerInfo = stash.TriggerInfo
		}
		fireBlockHook(cfg, req, check.CheckName(), reason, triggerInfo, false, resp.StatusCode)
		return resp
	}
	return nil
}

func runCheck(check SecurityCheck, req Request) (resp *Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			if panicErr, ok := r.(error); ok {
				err = panicErr
				return
			}
			err = fmt.Errorf("%v", r)
		}
	}()
	return check.Check(req), nil
}

func (p *SecurityCheckPipeline) handleCheckError(check SecurityCheck, req Request, err error, muted map[string]bool) *Response {
	cfg := p.config
	var redisErr *GuardRedisError
	if errors.As(err, &redisErr) && cfg != nil && cfg.RedisFailOpen {
		if !muted[check.CheckName()] {
			p.logger.Printf("Skipping check %s: Redis unavailable, failing open (redis_fail_open=True)", check.CheckName())
		}
		return nil
	}
	if !muted[check.CheckName()] {
		p.logger.Printf("Error in security check %s (%T): %v", check.CheckName(), err, err)
	}
	if cfg == nil || cfg.FailSecure {
		if !muted[check.CheckName()] {
			p.logger.Printf("Blocking request due to check error in fail-secure mode: %s", check.CheckName())
		}
		message := "Security check failed"
		if cfg != nil {
			if custom, ok := cfg.CustomErrorResponses[500]; ok && custom != "" {
				message = custom
			}
		}
		return errorResponse(500, message)
	}
	return nil
}

func (p *SecurityCheckPipeline) handleRebuildError(req Request, err error) *Response {
	p.logger.Printf("Error rebuilding security checks: %v", err)
	cfg := p.config
	if cfg == nil || !cfg.FailSecure {
		return nil
	}
	p.mu.RLock()
	empty := len(p.checks) == 0
	p.mu.RUnlock()
	if empty {
		panic(err)
	}
	message := "Security check failed"
	if custom, ok := cfg.CustomErrorResponses[500]; ok && custom != "" {
		message = custom
	}
	return errorResponse(500, message)
}

func RateLimitConfigFromSecurityConfig(cfg *SecurityConfig) RateLimitConfig {
	return RateLimitConfig{
		EnableRateLimiting:     cfg.EnableRateLimiting,
		RateLimit:              cfg.RateLimit,
		RateLimitWindow:        cfg.RateLimitWindow,
		EndpointRateLimits:     cfg.EndpointRateLimits,
		EnableRateLimitAutoBan: cfg.EnableRateLimitAutoBan,
		PassiveMode:            cfg.PassiveMode,
		EnableIPBanning:        cfg.EnableIPBanning,
		AutoBanThreshold:       cfg.AutoBanThreshold,
		AutoBanDuration:        cfg.AutoBanDuration,
		ThreatBanConfig:        cfg.ThreatBanConfig,
		RedisFailOpen:          cfg.RedisFailOpen,
	}
}

func BuildDefaultPipeline(cfg *SecurityConfig, ban *IPBanManager, rateLimit *RateLimitManager) (*SecurityCheckPipeline, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config must not be nil")
	}
	build := func() []SecurityCheck { return buildChecks(cfg, ban, rateLimit) }
	return NewSecurityCheckPipeline(build(), cfg, build), nil
}

func buildChecks(cfg *SecurityConfig, ban *IPBanManager, rateLimit *RateLimitManager) []SecurityCheck {
	specs := []struct {
		name     string
		excluded bool
		applies  func(cfg *SecurityConfig) bool
		build    func(cfg *SecurityConfig) SecurityCheck
	}{
		{"route_config", true, func(*SecurityConfig) bool { return false }, nil},
		{"emergency_mode", false, func(cfg *SecurityConfig) bool { return cfg.EmergencyMode || cfg.EnableDynamicRules }, nil},
		{"https_enforcement", false, func(cfg *SecurityConfig) bool { return cfg.EnforceHTTPS }, nil},
		{"request_logging", false, func(cfg *SecurityConfig) bool { return cfg.LogRequestLevel != "" }, nil},
		{"request_size_content", false, func(*SecurityConfig) bool { return false }, nil},
		{"required_headers", false, func(*SecurityConfig) bool { return false }, nil},
		{"authentication", false, func(*SecurityConfig) bool { return false }, nil},
		{"referrer", false, func(*SecurityConfig) bool { return false }, nil},
		{"custom_validators", false, func(*SecurityConfig) bool { return false }, nil},
		{"time_window", false, func(*SecurityConfig) bool { return false }, nil},
		{"cloud_ip_refresh", false, func(cfg *SecurityConfig) bool { return len(cfg.BlockCloudProviders) > 0 || cfg.EnableDynamicRules }, nil},
		{"ip_security", true, func(*SecurityConfig) bool { return true }, func(cfg *SecurityConfig) SecurityCheck {
			return &ipSecurityCheck{cfg: cfg, ban: ban, name: "ip_security"}
		}},
		{"cloud_provider", false, func(cfg *SecurityConfig) bool { return len(cfg.BlockCloudProviders) > 0 || cfg.EnableDynamicRules }, nil},
		{"user_agent", false, func(cfg *SecurityConfig) bool { return len(cfg.BlockedUserAgents) > 0 || cfg.EnableDynamicRules }, nil},
		{"rate_limit", true, func(cfg *SecurityConfig) bool { return cfg.EnableRateLimiting || len(cfg.EndpointRateLimits) > 0 }, func(cfg *SecurityConfig) SecurityCheck {
			return &rateLimitCheck{cfg: cfg, manager: rateLimit}
		}},
		{"suspicious_activity", false, func(cfg *SecurityConfig) bool { return cfg.EnablePenetrationDetection }, func(cfg *SecurityConfig) SecurityCheck {
			return &suspiciousActivityCheck{cfg: cfg, ban: ban, counts: &suspiciousCountStore{m: map[string]map[string]int{}}}
		}},
		{"custom_request", false, func(cfg *SecurityConfig) bool { return cfg.CustomRequestCheck != nil }, nil},
	}
	var checks []SecurityCheck
	for _, spec := range specs {
		if !spec.applies(cfg) {
			continue
		}
		if spec.build == nil {
			checks = append(checks, &unsupportedCheck{name: spec.name, excluded: spec.excluded, applies: spec.applies})
			continue
		}
		checks = append(checks, spec.build(cfg))
	}
	return checks
}
