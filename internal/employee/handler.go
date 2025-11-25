package employee

import (
	"database/sql"

	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(app *fiber.App, db *sql.DB) {
	app.Post("/api/employees", createEmployee(db))
	app.Post("/api/employees/:id/offboard", offboardEmployee(db))
	app.Put("/api/employees/:id", updateEmployee(db))
}
