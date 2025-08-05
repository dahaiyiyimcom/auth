package auth

type SessionData struct {
	Payload   string `json:"payload"`
	UserAgent string `json:"userAgent"`
	CreatedAt int64  `json:"created_at"`
}
