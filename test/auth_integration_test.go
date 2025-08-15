package test

import (
	"fmt"
	"github.com/couchbase/gocb/v2"
	"github.com/dahaiyiyimcom/auth/v4"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("Warning: could not load .env file, using system environment variables")
	}
}

var (
	storeInstance *auth.CouchbaseStore
	once          sync.Once
)

func GetCouchbaseStore(config auth.CouchbaseConfig) (*auth.CouchbaseStore, error) {
	var err error
	once.Do(func() {
		cluster, e := gocb.Connect(config.ConnStr, gocb.ClusterOptions{
			Username: config.Username,
			Password: config.Password,
		})
		if e != nil {
			err = e
			return
		}
		err = cluster.WaitUntilReady(config.Timeout, nil)
		if err != nil {
			panic(fmt.Sprintf("Cluster is not ready or credentials invalid: %v", err))
		}

		bucket := cluster.Bucket(config.BucketName)
		if e = bucket.WaitUntilReady(config.Timeout, nil); e != nil {
			err = e
			return
		}

		scope := bucket.Scope(config.Scope)
		collection := scope.Collection(config.Collection)

		storeInstance = &auth.CouchbaseStore{
			Cluster:    cluster,
			Bucket:     bucket,
			Collection: collection,
		}
	})

	return storeInstance, err
}

func getTestAuth() *auth.Auth {
	conf := auth.CouchbaseConfig{
		ConnStr:    os.Getenv("CB_CONN_STR"), // örn: "couchbase://127.0.0.1"
		Username:   os.Getenv("CB_USERNAME"), // örn: "Administrator"
		Password:   os.Getenv("CB_PASSWORD"), // örn: "password"
		BucketName: os.Getenv("CB_BUCKET"),   // örn: "auth-test"
		Scope:      os.Getenv("CB_SCOPE"),
		Collection: os.Getenv("CP_COLLECTION"),
		Timeout:    5 * time.Second,
	}
	cs, err := GetCouchbaseStore(conf)
	if err != nil {
		panic(err)
	}
	cfg := &auth.Config{
		JwtSecretKey:        "test-secret",
		Couchbase:           cs,
		EndpointPermissions: map[string]int{"/protected": 1},
	}

	return auth.New(cfg)
}

func TestCreateAccessToken_And_SaveSession(t *testing.T) {
	authStr := getTestAuth()

	token, err := authStr.CreateAccessToken("user123", "TestAgent", []int{1}, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}
	if token == "" {
		t.Fatal("CreateAccessToken returned empty token")
	}

	// Couchbase kaydını kontrol edelim
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token split expected 3 parts, got %d", len(parts))
	}
	signature := parts[2]
	if err := authStr.GetSessionFromCouchbase("user123", signature); err != nil {
		t.Fatalf("Session should exist in Couchbase: %v", err)
	}
}

func TestMiddleware_With_ValidToken(t *testing.T) {
	authStr := getTestAuth()

	token, err := authStr.CreateAccessToken("user123", "TestAgent", []int{1}, nil, nil)
	if err != nil {
		t.Fatalf("CreateAccessToken error: %v", err)
	}

	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		t.Errorf("token split expected 3 parts, got %d", len(tokenParts))
	}

	err = authStr.TokenVerify(tokenParts[2])
	if err != nil {
		t.Fatalf("TokenVerify error: %v", err)
	}

	app := fiber.New()
	app.Use(authStr.Middleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req, -1)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestMiddleware_With_InvalidToken(t *testing.T) {
	authStr := getTestAuth()

	app := fiber.New()
	app.Use(authStr.Middleware)
	app.Get("/protected", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.value")

	resp, _ := app.Test(req, -1)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}
