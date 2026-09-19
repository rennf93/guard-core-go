package guardcore

import (
	"fmt"
)

const CloudBlockedMsg = "Cloud provider IP not allowed"

func cloudBlockingEnabled(cfg *SecurityConfig) bool {
	return len(cfg.BlockCloudProviders) > 0 || cfg.EnableDynamicRules
}

func cloudApplies(cfg *SecurityConfig, routes []*RouteConfig) bool {
	return cloudBlockingEnabled(cfg) ||
		anyRoute(routes, func(rc *RouteConfig) bool { return len(rc.BlockCloudProviders) > 0 })
}

func cloudProvidersToCheck(routeConfig *RouteConfig, global []string) []string {
	if routeConfig != nil && len(routeConfig.BlockCloudProviders) > 0 {
		return routeConfig.BlockCloudProviders
	}
	if len(global) > 0 {
		return global
	}
	return nil
}

type cloudIPRefreshCheck struct {
	cfg     *SecurityConfig
	manager *CloudManager
}

func (c *cloudIPRefreshCheck) CheckName() string             { return "cloud_ip_refresh" }
func (c *cloudIPRefreshCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *cloudIPRefreshCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg != nil && cloudBlockingEnabled(cfg)
}

func (c *cloudIPRefreshCheck) Check(req Request) *Response {
	providers := cloudProvidersToCheck(req.State().RouteConfig, c.cfg.BlockCloudProviders)
	if len(providers) == 0 {
		return nil
	}
	ttl := c.cfg.CloudIPRefreshInterval
	now := c.manager.nowUnix()
	if now-c.manager.LastRefreshStamp() <= int64(ttl) {
		return nil
	}
	previous := c.manager.LastRefreshStamp()
	c.manager.SetLastRefreshStamp(now)
	scheduled := c.manager.ScheduleRefresh(providers, ttl, func() error {
		return c.manager.RefreshAsync(providers, ttl)
	})
	if !scheduled {
		c.manager.SetLastRefreshStamp(previous)
	}
	return nil
}

type cloudProviderCheck struct {
	cfg     *SecurityConfig
	manager *CloudManager
}

func (c *cloudProviderCheck) CheckName() string             { return "cloud_provider" }
func (c *cloudProviderCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *cloudProviderCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg != nil && cloudBlockingEnabled(cfg)
}

func (c *cloudProviderCheck) Check(req Request) *Response {
	state := req.State()
	if state.IsWhitelisted {
		return nil
	}
	ip := resolveClientIP(req)
	if ip == "" {
		return nil
	}
	if ShouldBypassCheck("clouds", state.RouteConfig) {
		return nil
	}
	providers := cloudProvidersToCheck(state.RouteConfig, c.cfg.BlockCloudProviders)
	if len(providers) == 0 {
		return nil
	}
	if !c.manager.IsCloudIP(ip, providers) {
		return nil
	}
	cfg := c.cfg
	LogActivity(req, LogOptions{
		LogType:             "suspicious",
		Reason:              fmt.Sprintf("Blocked cloud provider IP: %s", ip),
		Level:               cfg.LogSuspiciousLevel,
		PassiveMode:         cfg.PassiveMode,
		CheckName:           c.CheckName(),
		MutedCheckLogs:      cfg.MutedCheckLogs,
		OnBlock:             cfg.OnBlock,
		SensitiveHeaders:    cfg.LogSensitiveHeaders,
		SensitiveParams:     cfg.LogSensitiveParams,
		SensitiveBodyFields: cfg.LogSensitiveBodyFields,
	})
	if !cfg.PassiveMode {
		return createErrorResponse(cfg, 403, CloudBlockedMsg)
	}
	return nil
}

func (m *CloudManager) nowUnix() int64 { return m.nowFunc().Unix() }

func (m *CloudManager) InitializeRedis(redis RedisHandler, providers []string, ttl int) error {
	if redis == nil {
		return fmt.Errorf("redis handler must not be nil")
	}
	m.SetRedisHandler(redis)
	m.mu.Lock()
	current := m.store
	m.mu.Unlock()
	if current == nil {
		m.SetStore(NewRedisCloudIPStore(redis))
	}
	return m.RefreshAsync(providers, ttl)
}
