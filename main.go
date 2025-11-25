package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"

	"service-portal/internal/auth"
	"service-portal/internal/employee"
	"service-portal/pkg/database"
)

func main() {
	godotenv.Load()

	db := database.ConnectPostgres()

	app := fiber.New()

	// Protect all /api routes using Keycloak middleware
	app.Use("/api", auth.KeycloakMiddleware)

	// Employee REST API
	employee.RegisterRoutes(app, db)

	// Render UI pages
	app.Get("/", func(c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{}, "layouts/main")
	})

	log.Fatal(app.Listen(":8080"))
}
