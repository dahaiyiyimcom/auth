# GO AUTH
## What the purpose of this package?
The purpose of this package is to _generate jwt token_, _provide session control from Redis_ and _provide an authorization middleware_.

## How can use this package?
#### 1- First of all load packages and import.
```cmd 
go get "github.com/dahaiyiyimcom/auth/v4"
```
```go
import "github.com/dahaiyiyimcom/auth/v4"
```
#### 2- Secondly create Auth variable.
Create an "auth" directory and define a global variable there to get the Auth struct with the New method.
<br>Create GetAuth() method to use the auth variable in different directories.
```go 
var a = auth.New(&auth.Config{
    JwtSecretKey: string,
    Couchbase: auth.CouchbaseConfig{
        ConnStr:    string,
        Username:   string, 
        Password:   string,
        BucketName: string, 
        Scope:      string,
        Collection: string,
        Timeout:    time.Duration,
    },
    EndpointPermissions: map[string]int
})

func GetAuth() *auth.Auth {
return a
}

```
#### 3- Use gofiber/fiber/v2 for middleware.
```go 
app := fiber.New()
api := app.Group("/api")

a := auth.GetAuth()

api.Use(a.Middleware)
```
You can control auth.go file for requirement.

### Creating Access Token
You can generate tokens using the CreateAccessToken function, which is the method of the Auth struct.
<br>The generated access token is added to the AccessToken field in the Auth struct.
```go
token := a.CreateAccessToken("uuid3", "userAgent", nil, nil, nil)
```
The CreateAccess Token function takes two parameters. The first is the uuid of the token holder and the second is its role.
<br>However, if your system does not use role information, you can specify it as "nil".

### Adding to Couchbase
Couchbase NoSQL database is used to control the session of the users.
Each session is stored in Couchbase with a key in the format **uuid:tokenSignature**.
The stored data includes:
*   **Payload** (JWT payload)
*   **User-Agent**
*   **CreatedAt** timestamp

By using the SaveSessionToCouchbase function, the user’s session is saved to Couchbase.
```go
err := a.SaveSessionToCouchbase("uuid3", "tokenSignature", "user-agent-data")
if err != nil {
    panic(err)
}
```

### Deleting from Couchbase
If the user’s refresh token has expired or the user logs out, the session information is also deleted from Couchbase.
```go
err := a.DeleteSessionFromCouchbase("uuid3", "tokenSignature")
if err != nil {
    panic(err)
}
```

