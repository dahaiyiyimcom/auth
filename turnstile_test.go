package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// roundTripFunc lets a test supply the siteverify HTTP response inline without
// reaching the real Cloudflare endpoint.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

// jsonResp builds a siteverify-style HTTP response with the given status/body.
func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func newTestTurnstile(t *testing.T, client turnstileHTTPClient, hostname string) *Turnstile {
	t.Helper()
	var hostnames []string
	if hostname != "" {
		hostnames = []string{hostname}
	}
	return NewTurnstile(TurnstileConfig{
		SecretKey:         "test-secret",
		ExpectedHostnames: hostnames,
		HTTPClient:        client,
	})
}

func TestNewTurnstile_PanicsWithoutSecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on empty secret key, got none")
		}
	}()
	NewTurnstile(TurnstileConfig{SecretKey: "  "})
}

func TestVerify_MissingToken(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("siteverify must not be called when token is empty")
		return nil, nil
	}), "")
	if err := ts.Verify(context.Background(), "", ""); !errors.Is(err, ErrTurnstileMissingToken) {
		t.Fatalf("want ErrTurnstileMissingToken, got %v", err)
	}
}

func TestVerify_Success(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// The secret and token must reach siteverify as form fields.
		if err := req.ParseForm(); err == nil {
			if req.PostFormValue("response") != "tok" {
				t.Errorf("token not forwarded, got %q", req.PostFormValue("response"))
			}
		}
		return jsonResp(200, `{"success":true,"hostname":"stage2.dahaiyiyim.com"}`), nil
	}), "stage2.dahaiyiyim.com")
	if err := ts.Verify(context.Background(), "tok", "1.2.3.4"); err != nil {
		t.Fatalf("want success, got %v", err)
	}
}

func TestVerify_Rejected(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(200, `{"success":false,"error-codes":["invalid-input-response"]}`), nil
	}), "")
	if err := ts.Verify(context.Background(), "tok", ""); !errors.Is(err, ErrTurnstileFailed) {
		t.Fatalf("want ErrTurnstileFailed, got %v", err)
	}
}

// A reused token is Cloudflare's "timeout-or-duplicate" error — must be a hard
// failure, not a pass. This is why retries need a fresh token.
func TestVerify_ReusedToken(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(200, `{"success":false,"error-codes":["timeout-or-duplicate"]}`), nil
	}), "")
	if err := ts.Verify(context.Background(), "reused", ""); !errors.Is(err, ErrTurnstileFailed) {
		t.Fatalf("want ErrTurnstileFailed for reused token, got %v", err)
	}
}

func TestVerify_HostnameMismatch(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(200, `{"success":true,"hostname":"evil.example.com"}`), nil
	}), "stage2.dahaiyiyim.com")
	if err := ts.Verify(context.Background(), "tok", ""); !errors.Is(err, ErrTurnstileFailed) {
		t.Fatalf("want ErrTurnstileFailed on hostname mismatch, got %v", err)
	}
}

// Transport error (Cloudflare unreachable) must map to Unavailable, never pass.
func TestVerify_TransportError_FailsClosed(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: i/o timeout")
	}), "")
	if err := ts.Verify(context.Background(), "tok", ""); !errors.Is(err, ErrTurnstileUnavailable) {
		t.Fatalf("want ErrTurnstileUnavailable, got %v", err)
	}
}

func TestVerify_Non2xx_FailsClosed(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(500, `internal error`), nil
	}), "")
	if err := ts.Verify(context.Background(), "tok", ""); !errors.Is(err, ErrTurnstileUnavailable) {
		t.Fatalf("want ErrTurnstileUnavailable on 5xx, got %v", err)
	}
}

// --- Middleware HTTP-status mapping ---

func doReq(t *testing.T, app *fiber.App, token string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, "/guarded", nil)
	if token != "" {
		req.Header.Set(turnstileTokenHeader, token)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp.StatusCode
}

func buildApp(ts *Turnstile) *fiber.App {
	app := fiber.New()
	app.Post("/guarded", ts.Middleware(), func(c *fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	return app
}

func TestMiddleware_PassesOnSuccess(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(200, `{"success":true}`), nil
	}), "")
	if got := doReq(t, buildApp(ts), "tok"); got != fiber.StatusOK {
		t.Fatalf("want 200, got %d", got)
	}
}

func TestMiddleware_403OnMissingToken(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("must not call siteverify without a token")
		return nil, nil
	}), "")
	if got := doReq(t, buildApp(ts), ""); got != fiber.StatusForbidden {
		t.Fatalf("want 403, got %d", got)
	}
}

func TestMiddleware_403OnRejected(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResp(200, `{"success":false,"error-codes":["invalid-input-response"]}`), nil
	}), "")
	if got := doReq(t, buildApp(ts), "bad"); got != fiber.StatusForbidden {
		t.Fatalf("want 403, got %d", got)
	}
}

// The core fail-closed guarantee at the HTTP layer: Cloudflare down -> 503.
func TestMiddleware_503OnUnavailable(t *testing.T) {
	ts := newTestTurnstile(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	}), "")
	if got := doReq(t, buildApp(ts), "tok"); got != fiber.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", got)
	}
}

// A single widget serving multiple surfaces accepts any hostname in its
// allow-list (seller + application share one widget).
func TestVerify_MultipleHostnames(t *testing.T) {
	ts := NewTurnstile(TurnstileConfig{
		SecretKey:         "test-secret",
		ExpectedHostnames: []string{"shop.dahaiyiyim.com", "basvuru.dahaiyiyim.com"},
		HTTPClient: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResp(200, `{"success":true,"hostname":"basvuru.dahaiyiyim.com"}`), nil
		}),
	})
	if err := ts.Verify(context.Background(), "tok", ""); err != nil {
		t.Fatalf("want success for allow-listed hostname, got %v", err)
	}
}
