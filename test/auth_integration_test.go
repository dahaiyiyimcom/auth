package test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/dahaiyiyimcom/auth/v5"
	"github.com/gofiber/fiber/v2"
)

type memoryStore struct {
	mu       sync.RWMutex
	sessions map[string]auth.SessionData
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		sessions: make(map[string]auth.SessionData),
	}
}

func (m *memoryStore) SaveSession(_ context.Context, key string, session auth.SessionData, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("session ttl must be greater than zero")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[key] = session
	return nil
}

func (m *memoryStore) GetSession(_ context.Context, key string) (auth.SessionData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, ok := m.sessions[key]
	if !ok {
		return auth.SessionData{}, auth.ErrSessionNotFound
	}

	return session, nil
}

func (m *memoryStore) DeleteSession(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[key]; !ok {
		return auth.ErrSessionNotFound
	}

	delete(m.sessions, key)
	return nil
}

func getTestAuth() *auth.Auth {
	return auth.New(&auth.Config{
		JwtSecretKey: "test-secret",
		CookieName:   "test_access_token",
		SessionStore: newMemoryStore(),
		EndpointPermissions: map[string][]int{
			"/protected": {1, 2},
		},
	})
}

func TestCreateAccessTokenAndSaveSession(t *testing.T) {
	authStr := getTestAuth()

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1}, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}
	if token == "" {
		t.Fatal("CreateAccessToken returned empty token")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token split expected 3 parts, got %d", len(parts))
	}

	session, err := authStr.GetSession("user123", parts[2])
	if err != nil {
		t.Fatalf("session should exist in session store: %v", err)
	}
	if session.UserAgent != "TestAgent" {
		t.Fatalf("expected stored user agent to be TestAgent, got %q", session.UserAgent)
	}
}

func TestVerifyToken(t *testing.T) {
	authStr := getTestAuth()

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1, 2}, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}

	if err := authStr.VerifyToken(token); err != nil {
		t.Fatalf("VerifyToken error: %v", err)
	}
}

func TestMiddlewareWithValidToken(t *testing.T) {
	authStr := getTestAuth()

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1, 2}, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}

	app := fiber.New()
	app.Use(authStr.Middleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestMiddlewareWithInvalidToken(t *testing.T) {
	authStr := getTestAuth()

	app := fiber.New()
	app.Use(authStr.Middleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.value")

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestMiddlewareWithCookie(t *testing.T) {
	authStr := getTestAuth()

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{2}, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}

	app := fiber.New()
	app.Use(authStr.MiddlewareWithCookie)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "test_access_token",
		Value: token,
		Path:  "/",
	})

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestMiddlewareWithoutAccessTokenCookie(t *testing.T) {
	authStr := getTestAuth()

	app := fiber.New()
	app.Use(authStr.MiddlewareWithCookie)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestDeleteSession(t *testing.T) {
	authStr := getTestAuth()

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1}, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token split expected 3 parts, got %d", len(parts))
	}

	if err := authStr.DeleteSession("user123", parts[2]); err != nil {
		t.Fatalf("DeleteSession error: %v", err)
	}

	if _, err := authStr.GetSession("user123", parts[2]); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound after delete, got %v", err)
	}
}

func TestAllUserPermissionAllowsRolelessUsers(t *testing.T) {
	authStr := auth.New(&auth.Config{
		JwtSecretKey: "test-secret",
		CookieName:   "test_access_token",
		SessionStore: newMemoryStore(),
		EndpointPermissions: map[string][]int{
			"/protected": {auth.AllUser},
		},
	})

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}

	app := fiber.New()
	app.Use(authStr.Middleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}
