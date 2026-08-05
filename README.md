# GO AUTH

JWT token generation, Redis-backed session control, and Fiber authorization middleware.

## Installation

```bash
go get github.com/dahaiyiyimcom/auth/v5
```

```go
import "github.com/dahaiyiyimcom/auth/v5"
```

## Quick Start

Create the Redis-backed session store once and inject it into the auth package.

```go
store, err := auth.NewRedisStore(auth.RedisConfig{
    Addr:           "localhost:6379",
    Password:       "",
    DB:             0,
    ConnectTimeout: 5 * time.Second,
    KeyPrefix:      "auth:",
})
if err != nil {
    panic(err)
}
defer store.Close()

var a = auth.New(&auth.Config{
    JwtSecretKey: "secret_key",
    CookieName:   "access_token",
    SessionStore: store,
    EndpointPermissions: map[string][]int{
        "/api/admin": {auth.Admin},
        "/api/me":    {auth.AllUser},
    },
})
```

Use the middleware with Fiber:

```go
app := fiber.New()
api := app.Group("/api")

api.Use(a.Middleware)
```

Cookie-based auth is also available:

```go
api.Use(a.MiddlewareWithCookie)
```

## Create Access Token

`CreateAccessToken` generates the JWT and persists a matching Redis session keyed as `uuid:tokenSignature`.

```go
token, err := a.CreateAccessToken("uuid-123", "user-agent-data", nil, []int{auth.Admin}, nil, nil)
if err != nil {
    panic(err)
}
```

## Session Operations

Get and delete session records with the generic session methods:

```go
session, err := a.GetSession("uuid-123", "token-signature")
if err != nil {
    panic(err)
}

_ = session

if err := a.DeleteSession("uuid-123", "token-signature"); err != nil {
    panic(err)
}
```

## v4 to v5 Migration

- Module path changed to `github.com/dahaiyiyimcom/auth/v5`
- Couchbase-specific config and methods were removed
- Session persistence now uses the generic `SessionStore` interface
- `VerifyToken` replaces the old stateful token verification flow
