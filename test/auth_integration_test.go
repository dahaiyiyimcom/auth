package test

import (
	"context"
	"encoding/base64"
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

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1}, nil, nil, nil, nil)
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

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1, 2}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}

	if err := authStr.VerifyToken(token); err != nil {
		t.Fatalf("VerifyToken error: %v", err)
	}
}

func TestMiddlewareWithValidToken(t *testing.T) {
	authStr := getTestAuth()

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1, 2}, nil, nil, nil, nil)
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

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{2}, nil, nil, nil, nil)
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

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1}, nil, nil, nil, nil)
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

	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, nil, nil, nil, nil, nil)
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

// TestFromCookieVerifiesSignature ensures the cookie identity helpers reject a
// token whose payload was tampered with (forged claims kept with a stale/invalid
// signature) instead of trusting the forged claims — the gap the security scan
// flagged.
func TestFromCookieVerifiesSignature(t *testing.T) {
	authStr := getTestAuth()
	shopID := 7
	token, err := authStr.CreateAccessToken("user123", "TestAgent", nil, []int{1}, &shopID, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}

	// A genuine token resolves its claims.
	if uuid, err := authStr.GetUUIDFromCookie(token); err != nil || uuid != "user123" {
		t.Fatalf("GetUUIDFromCookie on valid token = %q, %v; want user123", uuid, err)
	}
	if got, err := authStr.GetShopIDFromCookie(token); err != nil || got != shopID {
		t.Fatalf("GetShopIDFromCookie on valid token = %d, %v; want %d", got, err, shopID)
	}

	// Tamper the payload (bump shop_id) but keep the original signature.
	parts := strings.Split(token, ".")
	forgedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"uuid":"attacker","roles":[1],"shop_id":999999}`))
	forged := parts[0] + "." + forgedPayload + "." + parts[2]

	if _, err := authStr.GetUUIDFromCookie(forged); err == nil {
		t.Fatal("GetUUIDFromCookie accepted a token with a payload that does not match its signature")
	}
	if _, err := authStr.GetShopIDFromCookie(forged); err == nil {
		t.Fatal("GetShopIDFromCookie accepted a forged shop_id")
	}
}

// TestGetAccessTokenCookieFirstWins ensures GetAccessTokenCookie returns the
// FIRST cookie of the configured name, matching fasthttp's ctx.Cookies used by
// handlers. Otherwise a request with two cookies of the same name could pass the
// middleware on one and be read by a handler as the other (duplicate-cookie bypass).
func TestGetAccessTokenCookieFirstWins(t *testing.T) {
	app := fiber.New()
	var got string
	app.Get("/", func(c *fiber.Ctx) error {
		v, _ := auth.GetAccessTokenCookie(c, "test_access_token")
		got = v
		return c.SendStatus(200)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Add("Cookie", "test_access_token=first")
	req.Header.Add("Cookie", "test_access_token=second")
	if _, err := app.Test(req); err != nil {
		t.Fatalf("app.Test error: %v", err)
	}
	if got != "first" {
		t.Fatalf("GetAccessTokenCookie = %q; want first (handlers read the first cookie)", got)
	}
}
