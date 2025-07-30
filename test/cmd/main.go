package main

import (
	"github.com/dahaiyiyimcom/auth/v3/test/authTest"
	"github.com/dahaiyiyimcom/auth/v3/test/handler"
	"github.com/gofiber/fiber/v2"
	"log"
)

func main() {

	app := fiber.New()
	app.Get("/get", handler.GetToken)

	a := authTest.GetAuth()

	api := app.Group("/api")
	api.Use(a.Middleware)

	//api.Get("/test/t", handler.Test)
	api.Get("/test/:uuid", handler.Test)

	err := app.Listen(":7777")
	if err != nil {
		log.Fatal(err)
	}
}
