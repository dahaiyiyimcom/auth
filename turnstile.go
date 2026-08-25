package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Turnstile verifies Cloudflare Turnstile tokens against the siteverify API.
//
// The widget runs in invisible mode on the frontend: the appearance is a
// frontend concern (data-appearance), so this backend layer only validates the
// resulting token. It is deliberately fail-closed — if siteverify cannot be
// reached within the timeout, the request is rejected rather than allowed
// through, so an outage of Cloudflare cannot silently disable bot protection.

const (
	// defaultTurnstileEndpoint is Cloudflare's siteverify URL.
	defaultTurnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	// defaultTurnstileTimeout bounds the outbound siteverify call. Kept short so
	// a slow Cloudflare cannot stall the protected login/register endpoints.
	defaultTurnstileTimeout = 2 * time.Second
	// turnstileTokenHeader is where the frontend places the freshly minted token.
	turnstileTokenHeader = "X-Turnstile-Token"
)

// Sentinel errors let callers branch on the failure mode via errors.Is.
var (
	// ErrTurnstileMissingToken is returned when the request carries no token.
	ErrTurnstileMissingToken = errors.New("turnstile: token is missing")
	// ErrTurnstileFailed is returned when siteverify rejects the token
	// (invalid, expired, or already used).
	ErrTurnstileFailed = errors.New("turnstile: verification failed")
	// ErrTurnstileUnavailable is returned when siteverify could not be reached
	// or answered in time. The middleware maps this to 503, never to success.
	ErrTurnstileUnavailable = errors.New("turnstile: verification service unavailable")
)

// turnstileHTTPClient is the minimal surface the verifier needs. Injecting it
// (rather than using http.DefaultClient directly) keeps the verifier unit
// testable without reaching the real Cloudflare endpoint.
type turnstileHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// TurnstileConfig configures a Turnstile verifier. SecretKey is required and
// must come from an environment variable per surface (never hardcoded).
type TurnstileConfig struct {
	// SecretKey is the per-surface Turnstile secret (consumer / seller /
	// application each have their own widget and secret).
	SecretKey string
	// Endpoint overrides the siteverify URL. Empty uses the Cloudflare default.
	Endpoint string
	// Timeout bounds the siteverify call. Zero uses defaultTurnstileTimeout.
	Timeout time.Duration
	// ExpectedHostnames, when non-empty, is the allow-list of hostnames the
	// solved challenge may report. A single widget serving multiple surfaces
	// (e.g. seller + application under dahaiyiyim.com) lists all of them here.
	// Empty skips the check and relies solely on Cloudflare's own
	// widget-hostname binding.
	ExpectedHostnames []string
	// HTTPClient overrides the outbound client (used in tests). Nil uses a
	// client bounded by Timeout.
	HTTPClient turnstileHTTPClient
}

// Turnstile verifies tokens for a single widget/surface.
type Turnstile struct {
	secretKey         string
	endpoint          string
	expectedHostnames map[string]struct{} // nil/empty = no hostname check
	httpClient        turnstileHTTPClient
}

// NewTurnstile builds a verifier from config. It panics on an empty secret key,
// mirroring auth.Config.init(): a misconfigured guard must fail at startup, not
// silently pass every request.
func NewTurnstile(cfg TurnstileConfig) *Turnstile {
	if strings.TrimSpace(cfg.SecretKey) == "" {
		panic("Turnstile init: secret key is required.")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = defaultTurnstileEndpoint
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTurnstileTimeout
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	var hostnames map[string]struct{}
	for _, h := range cfg.ExpectedHostnames {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" {
			continue
		}
		if hostnames == nil {
			hostnames = make(map[string]struct{})
		}
		hostnames[h] = struct{}{}
	}
	return &Turnstile{
		secretKey:         cfg.SecretKey,
		endpoint:          endpoint,
		expectedHostnames: hostnames,
		httpClient:        client,
	}
}

// siteverifyResponse is Cloudflare's siteverify JSON body.
type siteverifyResponse struct {
	Success     bool     `json:"success"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
	ErrorCodes  []string `json:"error-codes"`
}

// Verify checks a single token against siteverify. remoteIP is optional (the
// caller's IP, forwarded to Cloudflare for scoring); pass "" to omit it.
//
// It returns nil on success, ErrTurnstileFailed when the token is rejected,
// and ErrTurnstileUnavailable when siteverify could not be consulted (timeout,
// transport error, or a non-2xx/undecodable response). The unavailable case is
// wrapped so callers fail closed.
func (t *Turnstile) Verify(ctx context.Context, token, remoteIP string) error {
	if strings.TrimSpace(token) == "" {
		return ErrTurnstileMissingToken
	}

	form := url.Values{}
	form.Set("secret", t.secretKey)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrTurnstileUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTurnstileUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: siteverify status %d", ErrTurnstileUnavailable, resp.StatusCode)
	}

	var body siteverifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("%w: decode response: %v", ErrTurnstileUnavailable, err)
	}

	if !body.Success {
		return fmt.Errorf("%w: %s", ErrTurnstileFailed, strings.Join(body.ErrorCodes, ","))
	}

	if len(t.expectedHostnames) > 0 {
		if _, ok := t.expectedHostnames[strings.ToLower(body.Hostname)]; !ok {
			return fmt.Errorf("%w: unexpected hostname %q", ErrTurnstileFailed, body.Hostname)
		}
	}

	return nil
}

// Middleware returns a Fiber handler that guards a route with Turnstile. The
// token is read from the X-Turnstile-Token header (the frontend does not place
// it in an axios interceptor — only on the specific protected forms).
//
// Failure mapping:
//   - missing/invalid/expired/reused token -> 403
//   - siteverify unreachable (fail-closed)  -> 503
func (t *Turnstile) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		token := ctx.Get(turnstileTokenHeader)

		// ctx.Context() carries Fiber's request-scoped deadline; Verify inherits
		// it so a client cancel or server shutdown aborts the outbound call too.
		err := t.Verify(ctx.Context(), token, ctx.IP())
		if err == nil {
			return ctx.Next()
		}

		response := &Response{}
		switch {
		case errors.Is(err, ErrTurnstileUnavailable):
			// Fail closed: never let a Cloudflare outage wave requests through.
			response.Message = "turnstile verification unavailable"
			return response.HttpResponse(ctx, fiber.StatusServiceUnavailable)
		default:
			// Missing, invalid, expired, reused, or hostname mismatch.
			response.Message = "turnstile verification failed"
			return response.HttpResponse(ctx, fiber.StatusForbidden)
		}
	}
}
