package guardcore

const (
	DefaultRateLimit        = 10
	DefaultRateLimitWindow  = 60
	DefaultAutoBanThreshold = 10
	DefaultAutoBanDuration  = 3600
	maxTrackedRateLimitKeys = 10000
	RateLimitBlockedStatus  = 429
	RateLimitBlockedMessage = "Too many requests"
)

type RateLimitEntry struct {
	Requests int
	Window   int
}

type ThreatBanEntry struct {
	Threshold int
	Duration  int
}

type RateLimitConfig struct {
	EnableRateLimiting     bool
	RateLimit              int
	RateLimitWindow        int
	EndpointRateLimits     map[string]RateLimitEntry
	EnableRateLimitAutoBan bool
	PassiveMode            bool
	EnableIPBanning        bool
	AutoBanThreshold       int
	AutoBanDuration        int
	ThreatBanConfig        map[string]ThreatBanEntry
	RedisFailOpen          bool
}

func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		EnableRateLimiting:     true,
		RateLimit:              DefaultRateLimit,
		RateLimitWindow:        DefaultRateLimitWindow,
		EndpointRateLimits:     map[string]RateLimitEntry{},
		EnableRateLimitAutoBan: false,
		PassiveMode:            false,
		EnableIPBanning:        false,
		AutoBanThreshold:       DefaultAutoBanThreshold,
		AutoBanDuration:        DefaultAutoBanDuration,
		ThreatBanConfig:        map[string]ThreatBanEntry{},
		RedisFailOpen:          false,
	}
}
