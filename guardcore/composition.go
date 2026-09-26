package guardcore

import (
	"errors"
	"log"
	"slices"
	"sync"
)

type Engine struct {
	Config    *SecurityConfig
	Routes    *RouteRegistry
	Redis     *RedisManager
	Ban       *IPBanManager
	RateLimit *RateLimitManager
	Cloud     *CloudManager

	pipeline       *SecurityCheckPipeline
	exclusions     exclusionMatcher
	initializeOnce sync.Once
	initializeErr  error
}

func NewEngine(cfg *SecurityConfig) (*Engine, error) {
	if cfg == nil {
		return nil, errors.New("config must not be nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	routes := NewRouteRegistry()
	redisManager := NewRedisManager(RedisConfig{URL: cfg.RedisURL, Prefix: cfg.RedisPrefix, EnableRedis: cfg.EnableRedis})
	ban := NewIPBanManager(redisManager, cfg.TrustedProxies)
	rateLimit := NewRateLimitManager(RateLimitConfigFromSecurityConfig(cfg), redisManager, ban)
	pipeline, err := BuildDefaultPipeline(cfg, ban, rateLimit, routes)
	if err != nil {
		return nil, err
	}
	return &Engine{
		Config:    cfg,
		Routes:    routes,
		Redis:     redisManager,
		Ban:       ban,
		RateLimit: rateLimit,
		Cloud:     DefaultCloudManager,
		pipeline:  pipeline,
		exclusions: exclusionMatcher{
			cfg: cfg,
		},
	}, nil
}

func (e *Engine) Initialize() error {
	e.initializeOnce.Do(func() {
		e.initializeErr = e.startup()
	})
	return e.initializeErr
}

func (e *Engine) startup() error {
	if !e.Config.EnableRedis {
		return e.refreshCloudRangesWithoutRedis()
	}
	if err := e.Redis.Initialize(); err != nil {
		if e.Config.RedisFailOpen {
			log.Printf("Redis unavailable during initialization, failing open: %v", err)
			return e.refreshCloudRangesWithoutRedis()
		}
		return err
	}
	if len(e.Config.BlockCloudProviders) > 0 {
		if err := e.Cloud.InitializeRedis(e.Redis, e.Config.BlockCloudProviders, e.Config.CloudIPRefreshInterval); err != nil {
			return err
		}
	}
	if err := e.Ban.InitializeRedis(e.Redis); err != nil {
		return err
	}
	e.RateLimit.InitializeRedis(e.Redis)
	return nil
}

func (e *Engine) refreshCloudRangesWithoutRedis() error {
	if len(e.Config.BlockCloudProviders) == 0 {
		return nil
	}
	return e.Cloud.RefreshAsync(e.Config.BlockCloudProviders, e.Config.CloudIPRefreshInterval)
}

func (e *Engine) Check(req Request) *Response {
	state := req.State()
	if e.exclusions.matches(req.URLPath()) {
		state.ExclusionScoped = true
	}
	if routeConfig := e.Routes.Get(state.GuardRouteID); routeConfig != nil && routeConfig.HasBypass("all") && !e.Config.PassiveMode {
		return nil
	}
	return e.pipeline.Execute(req)
}

func (e *Engine) CreateErrorResponse(statusCode int, defaultMessage string) *Response {
	return createErrorResponse(e.Config, statusCode, defaultMessage)
}

// ResponseHeaders computes the security headers the adapter must put on every
// normal (pass-through) response, mirroring the reference where the response
// factory applies security_headers_manager.get_headers on the way out
// (guard_core/core/responses/factory.py process_response). Blocked responses
// already carry the headers: the pipeline's error factory applies them
// engine-side. An empty map means the feature is disabled.
func (e *Engine) ResponseHeaders() map[string]string {
	return responseHeaders(e.Config)
}

func (e *Engine) Close() error {
	return e.Redis.Close()
}

type exclusionMatcher struct {
	mu      sync.Mutex
	cfg     *SecurityConfig
	source  []string
	entries []string
}

func (m *exclusionMatcher) matches(path string) bool {
	normalized, ok := normalizeURLPath(path)
	if !ok {
		return false
	}
	return pathMatchesExclusions(normalized, m.current())
}

func (m *exclusionMatcher) current() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Equal(m.source, m.cfg.ExcludePaths) {
		m.source = append([]string(nil), m.cfg.ExcludePaths...)
		m.entries = nil
		for _, entry := range m.cfg.ExcludePaths {
			if normalized, ok := normalizeURLPath(entry); ok {
				m.entries = append(m.entries, normalized)
			}
		}
	}
	return m.entries
}
