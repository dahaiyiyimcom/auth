package auth

import "github.com/gofiber/fiber/v2"

type Response struct {
	Message string `json:"message"`
	Data    any    `json:"data"`
}

func (response *Response) HttpResponse(ctx *fiber.Ctx, status int) error {
	return ctx.Status(status).JSON(response)
}
