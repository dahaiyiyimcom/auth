package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type HeaderConfig struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

type PayloadConfig struct {
	Uuid      string `json:"uuid"`
	Roles     []int  `json:"roles"`
	ShopID    *int   `json:"shop_id,omitempty"`
	CompanyID *int   `json:"company_id,omitempty"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

func CreateJWT(secretKey []byte, payload PayloadConfig) (string, string, string, string, error) {
	header := HeaderConfig{Alg: "HS256", Typ: "JWT"}

	jsonHeader, _ := json.Marshal(header)
	jsonPayload, _ := json.Marshal(payload)

	encodedHeader := base64.RawURLEncoding.EncodeToString(jsonHeader)
	encodedPayload := base64.RawURLEncoding.EncodeToString(jsonPayload)
	headerPayload := encodedHeader + "." + encodedPayload

	hasher := hmac.New(sha256.New, secretKey)
	hasher.Write([]byte(headerPayload))
	signature := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	token := headerPayload + "." + signature
	return encodedHeader, encodedPayload, token, signature, nil
}

func VerifyJWT(secretKey []byte, header, payload, signature string) error {
	data := header + "." + payload
	hasher := hmac.New(sha256.New, secretKey)
	hasher.Write([]byte(data))
	expectedSignature := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	if signature != expectedSignature {
		return errors.New("invalid token signature")
	}
	return nil
}

func DecodePayload(encodedPayload string) (PayloadConfig, error) {
	var payload PayloadConfig
	decoded, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return payload, err
	}
	err = json.Unmarshal(decoded, &payload)
	return payload, err
}
