package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/couchbase/gocb/v2"
	"github.com/dahaiyiyimcom/auth/v4/pkg"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

type Auth struct {
	Header              string
	Payload             string
	JwtSecretKey        []byte
	AccessToken         string
	Couchbase           *CouchbaseStore
	EndPointPermissions map[string]int
}

func New(config *Config) *Auth {
	auth := &Auth{
		JwtSecretKey:        []byte(config.JwtSecretKey),
		Couchbase:           config.Couchbase,
		EndPointPermissions: config.EndpointPermissions,
	}
	return auth
}

// CreateAccessToken generates a new JWT token with the given user information
func (a *Auth) CreateAccessToken(uuid, userAgent string, roles []int, shopId, companyId *int) (string, error) {
	payload := PayloadConfig{
		Uuid:      uuid,
		Roles:     roles,
		ShopID:    shopId,
		CompanyID: companyId,
		ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	// Use CreateJWT to generate token and signature
	var token, signature string
	var err error
	a.Header, a.Payload, token, signature, err = CreateJWT(a.JwtSecretKey, payload)
	if err != nil {
		return "", err
	}

	// Save session in Couchbase
	err = a.SaveSessionToCouchbase(uuid, signature, userAgent)
	if err != nil {
		return "", err
	}

	return token, nil
}

// TokenVerify verifies the token signature
func (a *Auth) TokenVerify(signature string) error {
	return VerifyJWT(a.JwtSecretKey, a.Header, a.Payload, signature)
}

// GetUUID extracts the UUID from the token
func (a *Auth) GetUUID(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("invalid token")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", errors.New("malformed token")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	authTokenParts := strings.Split(token, ".")
	if len(authTokenParts) != 3 {
		return "", errors.New("malformed token")
	}

	payloadBase64, _ := base64.RawURLEncoding.DecodeString(authTokenParts[1])
	var payload PayloadConfig
	if err := json.Unmarshal(payloadBase64, &payload); err != nil {
		return "", errors.New(err.Error())
	}

	return payload.Uuid, nil
}

// GetShopID extracts the ShopID from the token
func (a *Auth) GetShopID(authHeader string) (int, error) {
	if authHeader == "" {
		return 0, errors.New("invalid token")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return 0, errors.New("malformed token")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	authTokenParts := strings.Split(token, ".")
	if len(authTokenParts) != 3 {
		return 0, errors.New("malformed token")
	}

	payloadBase64, _ := base64.RawURLEncoding.DecodeString(authTokenParts[1])
	var payload PayloadConfig
	if err := json.Unmarshal(payloadBase64, &payload); err != nil {
		return 0, errors.New(err.Error())
	}

	if payload.ShopID == nil {
		return 0, errors.New("shopID is nil")
	}

	return *payload.ShopID, nil
}

// GetCompanyID extracts the CompanyID from the token
func (a *Auth) GetCompanyID(authHeader string) (int, error) {
	if authHeader == "" {
		return 0, errors.New("invalid token")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return 0, errors.New("malformed token")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	authTokenParts := strings.Split(token, ".")
	if len(authTokenParts) != 3 {
		return 0, errors.New("malformed token")
	}

	payloadBase64, _ := base64.RawURLEncoding.DecodeString(authTokenParts[1])
	var payload PayloadConfig
	if err := json.Unmarshal(payloadBase64, &payload); err != nil {
		return 0, errors.New(err.Error())
	}

	if payload.CompanyID == nil {
		return 0, errors.New("companyID is nil")
	}

	return *payload.CompanyID, nil
}

// Middleware performs authentication and authorization
func (a *Auth) Middleware(ctx *fiber.Ctx) error {
	var response Response
	// 1. Authorization header check
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		response.Message = "missing authorization header"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		response.Message = "invalid authorization format"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}
	// 2. Parse token
	a.AccessToken = strings.TrimPrefix(authHeader, "Bearer ")
	tokenParts := strings.Split(a.AccessToken, ".")
	if len(tokenParts) != 3 {
		response.Message = "malformed token"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}

	headerPart, payloadPart, signature := tokenParts[0], tokenParts[1], tokenParts[2]
	a.Header, a.Payload = headerPart, payloadPart
	// 3. Decode payload
	payload, err := DecodePayload(payloadPart)
	if err != nil {
		response.Message = "invalid payload"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}
	// 4. Verify signature
	if err := VerifyJWT(a.JwtSecretKey, headerPart, payloadPart, signature); err != nil {
		response.Message = "invalid token signature"
		return response.HttpResponse(ctx, fiber.StatusForbidden)
	}
	// 5. Check expiration
	if payload.ExpiresAt < time.Now().Unix() {
		response.Message = "token expired"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}

	// 6. Validate session in Couchbase
	err = a.GetSessionFromCouchbase(payload.Uuid, signature)
	if err != nil {
		response.Message = "session not found or invalid"
		return response.HttpResponse(ctx, fiber.StatusUnauthorized)
	}

	// 7. Authorization: Check user roles for the requested endpoint
	requestedPath := ctx.Path()
	matchedPermission, matched := pkg.MatchPathWithPermission(requestedPath, a.EndPointPermissions)
	if !matched {
		response.Message = "access denied: endpoint not recognized"
		return response.HttpResponse(ctx, fiber.StatusForbidden)
	}

	// Check if user's roles include the required permission
	if !PermissionsContains(payload.Roles, matchedPermission) {
		response.Message = "access denied"
		return response.HttpResponse(ctx, fiber.StatusForbidden)
	}

	return ctx.Next()
}

func (a *Auth) SaveSessionToCouchbase(uuid, tokenSignature, userAgent string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := uuid + ":" + tokenSignature

	session := SessionData{
		Payload:   a.Payload,
		UserAgent: userAgent,
		CreatedAt: time.Now().Unix(),
	}

	_, err := a.Couchbase.Collection.Upsert(key, session, &gocb.UpsertOptions{Context: ctx})
	return err
}

func (a *Auth) GetSessionFromCouchbase(uuid, tokenSignature string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := uuid + ":" + tokenSignature

	_, err := a.Couchbase.Collection.Get(key, &gocb.GetOptions{Context: ctx})
	return err
}

func (a *Auth) DeleteSessionFromCouchbase(uuid, tokenSignature string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	key := uuid + ":" + tokenSignature

	_, err := a.Couchbase.Collection.Remove(key, &gocb.RemoveOptions{Context: ctx})
	return err
}
