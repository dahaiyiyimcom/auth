package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dahaiyiyimcom/auth/v5/pkg"
	"github.com/gofiber/fiber/v2"
)

type Auth struct {
	JwtSecretKey        []byte
	CookieName          string
	SessionStore        SessionStore
	EndPointPermissions map[string][]int
	AccessTokenTTL      time.Duration
	StoreTimeout        time.Duration
}

func New(config *Config) *Auth {
	config.init()

	return &Auth{
		JwtSecretKey:        []byte(config.JwtSecretKey),
		CookieName:          config.CookieName,
		SessionStore:        config.SessionStore,
		EndPointPermissions: config.EndpointPermissions,
		AccessTokenTTL:      config.AccessTokenTTL,
		StoreTimeout:        config.StoreTimeout,
	}
}

// CreateAccessToken generates a new JWT token with the given user information.
func (a *Auth) CreateAccessToken(uuid, userAgent string, email *string, roles []int, shopId, companyId *int) (string, error) {
	now := time.Now()
	payload := PayloadConfig{
		Uuid:      uuid,
		Roles:     roles,
		Email:     email,
		ShopID:    shopId,
		CompanyID: companyId,
		ExpiresAt: now.Add(a.AccessTokenTTL).Unix(),
		IssuedAt:  now.Unix(),
	}

	_, encodedPayload, token, signature, err := CreateJWT(a.JwtSecretKey, payload)
	if err != nil {
		return "", err
	}

	session := SessionData{
		Payload:   encodedPayload,
		UserAgent: userAgent,
		CreatedAt: now.Unix(),
		ExpiresAt: payload.ExpiresAt,
	}

	if err := a.SaveSession(uuid, signature, session); err != nil {
		return "", err
	}

	return token, nil
}

// VerifyToken validates the token structure, signature, and expiration.
func (a *Auth) VerifyToken(accessToken string) error {
	_, _, err := a.validateAccessToken(accessToken)
	return err
}

// GetUUID extracts the UUID from an Authorization header.
func (a *Auth) GetUUID(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("invalid token")
	}

	token, ok := bearerTokenFromHeader(authHeader)
	if !ok {
		return "", errors.New("malformed token")
	}

	payload, err := decodeTokenPayload(token)
	if err != nil {
		return "", err
	}

	return payload.Uuid, nil
}

func (a *Auth) GetUUIDFromCookie(token string) (string, error) {
	payload, err := decodeTokenPayload(token)
	if err != nil {
		return "", err
	}

	return payload.Uuid, nil
}

// GetShopID extracts the ShopID from an Authorization header.
func (a *Auth) GetShopID(authHeader string) (int, error) {
	if authHeader == "" {
		return 0, errors.New("invalid token")
	}

	token, ok := bearerTokenFromHeader(authHeader)
	if !ok {
		return 0, errors.New("malformed token")
	}

	payload, err := decodeTokenPayload(token)
	if err != nil {
		return 0, err
	}

	if payload.ShopID == nil {
		return 0, errors.New("shopID is nil")
	}

	return *payload.ShopID, nil
}

func (a *Auth) GetShopIDFromCookie(token string) (int, error) {
	payload, err := decodeTokenPayload(token)
	if err != nil {
		return 0, err
	}
	if payload.ShopID == nil {
		return 0, errors.New("shopID is nil")
	}

	return *payload.ShopID, nil
}

// GetCompanyID extracts the CompanyID from an Authorization header.
func (a *Auth) GetCompanyID(authHeader string) (int, error) {
	if authHeader == "" {
		return 0, errors.New("invalid token")
	}

	token, ok := bearerTokenFromHeader(authHeader)
	if !ok {
		return 0, errors.New("malformed token")
	}

	payload, err := decodeTokenPayload(token)
	if err != nil {
		return 0, err
	}

	if payload.CompanyID == nil {
		return 0, errors.New("companyID is nil")
	}

	return *payload.CompanyID, nil
}

func (a *Auth) GetCompanyIDFromCookie(token string) (int, error) {
	payload, err := decodeTokenPayload(token)
	if err != nil {
		return 0, err
	}
	if payload.CompanyID == nil {
		return 0, errors.New("shopID is nil")
	}

	return *payload.CompanyID, nil
}

// Middleware performs authentication and authorization with the Authorization header.
func (a *Auth) Middleware(ctx *fiber.Ctx) error {
	var response Response

	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		response.Message = "missing authorization header"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}

	accessToken, ok := bearerTokenFromHeader(authHeader)
	if !ok {
		response.Message = "invalid authorization format"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}

	payload, signature, err := a.validateAccessToken(accessToken)
	if err != nil {
		return authErrorResponse(ctx, err, &response)
	}

	if _, err := a.GetSession(payload.Uuid, signature); err != nil {
		response.Message = "session not found or invalid"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}

	requestedPath := ctx.Path()
	matchedPermission, matched := pkg.MatchPathWithPermission(requestedPath, a.EndPointPermissions)
	if !matched {
		response.Message = "access denied: endpoint not recognized"
		return response.HttpResponse(ctx, fiber.StatusForbidden)
	}

	if !PermissionsContains(payload.Roles, matchedPermission) {
		response.Message = "access denied"
		return response.HttpResponse(ctx, fiber.StatusForbidden)
	}

	return ctx.Next()
}

// MiddlewareWithCookie performs authentication and authorization with the configured cookie.
func (a *Auth) MiddlewareWithCookie(ctx *fiber.Ctx) error {
	var response Response

	accessToken, ok := GetAccessTokenCookie(ctx, a.CookieName)
	if !ok {
		response.Message = "access token missing"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}

	payload, signature, err := a.validateAccessToken(accessToken)
	if err != nil {
		return authErrorResponse(ctx, err, &response)
	}

	if _, err := a.GetSession(payload.Uuid, signature); err != nil {
		response.Message = "session not found or invalid"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}

	requestedPath := ctx.Path()
	matchedPermission, matched := pkg.MatchPathWithPermission(requestedPath, a.EndPointPermissions)
	if !matched {
		response.Message = "access denied: endpoint not recognized"
		return response.HttpResponse(ctx, fiber.StatusForbidden)
	}
	if !PermissionsContains(payload.Roles, matchedPermission) {
		response.Message = "access denied"
		return response.HttpResponse(ctx, fiber.StatusForbidden)
	}

	return ctx.Next()
}

func (a *Auth) SaveSession(uuid, tokenSignature string, session SessionData) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.StoreTimeout)
	defer cancel()

	ttl := time.Until(time.Unix(session.ExpiresAt, 0))
	if ttl <= 0 {
		return errors.New("session ttl expired")
	}

	return a.SessionStore.SaveSession(ctx, sessionKey(uuid, tokenSignature), session, ttl)
}

func (a *Auth) GetSession(uuid, tokenSignature string) (SessionData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), a.StoreTimeout)
	defer cancel()

	return a.SessionStore.GetSession(ctx, sessionKey(uuid, tokenSignature))
}

func (a *Auth) DeleteSession(uuid, tokenSignature string) error {
	ctx, cancel := context.WithTimeout(context.Background(), a.StoreTimeout)
	defer cancel()

	return a.SessionStore.DeleteSession(ctx, sessionKey(uuid, tokenSignature))
}

func GetAccessTokenCookie(c *fiber.Ctx, cookieName string) (string, bool) {
	var value string
	found := false

	c.Context().Request.Header.VisitAllCookie(func(key, val []byte) {
		if strings.EqualFold(string(key), cookieName) {
			value = string(val)
			found = true
		}
	})

	return value, found
}

func bearerTokenFromHeader(authHeader string) (string, bool) {
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return "", false
	}

	return strings.TrimPrefix(authHeader, "Bearer "), true
}

func decodeTokenPayload(token string) (PayloadConfig, error) {
	_, payloadPart, _, err := SplitJWT(token)
	if err != nil {
		return PayloadConfig{}, err
	}

	payloadBase64, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return PayloadConfig{}, err
	}

	var payload PayloadConfig
	if err := json.Unmarshal(payloadBase64, &payload); err != nil {
		return PayloadConfig{}, err
	}

	return payload, nil
}

func (a *Auth) validateAccessToken(accessToken string) (PayloadConfig, string, error) {
	headerPart, payloadPart, signature, err := SplitJWT(accessToken)
	if err != nil {
		return PayloadConfig{}, "", errors.New("malformed token")
	}

	payload, err := DecodePayload(payloadPart)
	if err != nil {
		return PayloadConfig{}, "", errors.New("invalid payload")
	}

	if err := VerifyJWT(a.JwtSecretKey, headerPart, payloadPart, signature); err != nil {
		return PayloadConfig{}, "", errors.New("invalid token signature")
	}

	if payload.ExpiresAt < time.Now().Unix() {
		return PayloadConfig{}, "", errors.New("token expired")
	}

	return payload, signature, nil
}

func authErrorResponse(ctx *fiber.Ctx, err error, response *Response) error {
	switch err.Error() {
	case "invalid token signature":
		response.Message = err.Error()
		return response.HttpResponse(ctx, fiber.StatusForbidden)
	case "malformed token", "invalid payload", "token expired":
		response.Message = err.Error()
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	default:
		response.Message = "invalid token"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}
}
