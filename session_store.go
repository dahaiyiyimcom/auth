package auth

import (
	"context"
	"errors"
	"time"
)

var ErrSessionNotFound = errors.New("session not found")

type SessionStore interface {
	SaveSession(ctx context.Context, key string, session SessionData, ttl time.Duration) error
	GetSession(ctx context.Context, key string) (SessionData, error)
	DeleteSession(ctx context.Context, key string) error
}

func sessionKey(uuid, tokenSignature string) string {
	return uuid + ":" + tokenSignature
}
