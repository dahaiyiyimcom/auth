package auth

import "time"

const (
	defaultCookieName     = "access_token"
	defaultAccessTokenTTL = 15 * time.Minute
	defaultStoreTimeout   = 5 * time.Second
)

type Config struct {
	JwtSecretKey        string
	CookieName          string
	SessionStore        SessionStore
	EndpointPermissions map[string][]int
	AccessTokenTTL      time.Duration
	StoreTimeout        time.Duration
}

func (cfg *Config) init() {
	if cfg.CookieName == "" {
		cfg.CookieName = defaultCookieName
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = defaultAccessTokenTTL
	}
	if cfg.StoreTimeout <= 0 {
		cfg.StoreTimeout = defaultStoreTimeout
	}
	if cfg.JwtSecretKey == "" {
		panic("Auth Configuration init: JWT secret key is required.")
	}
	if cfg.SessionStore == nil {
		panic("Auth Configuration init: session store is required.")
	}
}
