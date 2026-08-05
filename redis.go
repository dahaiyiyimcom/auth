package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisConfig struct {
	Addr           string
	Password       string
	DB             int
	PoolSize       int
	MinIdleConns   int
	DialTimeout    time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	ConnectTimeout time.Duration
	KeyPrefix      string
}

type RedisStore struct {
	client    *redis.Client
	keyPrefix string
}

func NewRedisStore(config RedisConfig) (*RedisStore, error) {
	if config.Addr == "" {
		return nil, errors.New("redis addr is required")
	}

	client := redis.NewClient(&redis.Options{
		Addr:         config.Addr,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		DialTimeout:  config.DialTimeout,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	})

	connectTimeout := config.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = defaultStoreTimeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, err
	}

	return &RedisStore{
		client:    client,
		keyPrefix: config.KeyPrefix,
	}, nil
}

func (r *RedisStore) SaveSession(ctx context.Context, key string, session SessionData, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("session ttl must be greater than zero")
	}

	payload, err := json.Marshal(session)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, r.prefixedKey(key), payload, ttl).Err()
}

func (r *RedisStore) GetSession(ctx context.Context, key string) (SessionData, error) {
	value, err := r.client.Get(ctx, r.prefixedKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return SessionData{}, ErrSessionNotFound
		}
		return SessionData{}, err
	}

	var session SessionData
	if err := json.Unmarshal(value, &session); err != nil {
		return SessionData{}, err
	}

	return session, nil
}

func (r *RedisStore) DeleteSession(ctx context.Context, key string) error {
	deleted, err := r.client.Del(ctx, r.prefixedKey(key)).Result()
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *RedisStore) Close() error {
	return r.client.Close()
}

func (r *RedisStore) prefixedKey(key string) string {
	return r.keyPrefix + key
}
