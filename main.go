package main

import (
	"database/sql"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
)

func main() {
	// kijkt of de database gegevens in de .env staan
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		log.Fatal("POSTGRES_DSN is niet gezet")
	}

	//DB connectie
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}

	// als de tabel nog niet is aangemaakt, wordt die aangemaakt.
	if err := ensureTable(db); err != nil {
		log.Fatal(err)
	}

	app := fiber.New()

	//healthcheck
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// onboard functie
	app.Post("/onboard", func(c *fiber.Ctx) error {
		var body struct {
			Name       string `json:"name"`
			Email      string `json:"email"`
			Department string `json:"department"`
			Role       string `json:"role"`
		}

		if err := c.BodyParser(&body); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
		}

		if body.Name == "" || body.Email == "" || body.Department == "" || body.Role == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing fields"})
		}

		var id int
		err := db.QueryRow(`
			INSERT INTO employees (name, email, department, role, status)
			VALUES ($1, $2, $3, $4, 'active')
			RETURNING id`,
			body.Name, body.Email, body.Department, body.Role,
		).Scan(&id)
		if err != nil {
			log.Println("insert error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "db error"})
		}
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"message": "employee onboarded",
			"id":      id,
		})
	})

	log.Println("Service luistert op :8080")
	log.Fatal(app.Listen(":8080"))
}

func ensureTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS employees (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100) NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		department VARCHAR(100) NOT NULL,
		role VARCHAR(50) NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'active',
		created_at TIMESTAMP DEFAULT NOW()
	);`
	_, err := db.Exec(query)
	return err
}

/*
	type employee struct {
	ID        int `json:"id"`
	NAME      string `json:"name"`
	EMAIL     string `json:"email"`
	DEPARTMENT string `json:"department"`
	ROLE      string `json:"role"`
	STATUS    string `json:"status"`
}



	var err error
	db, err = initDB()
	if err != nil {
		log.Fatalf("db connect error")
	}
	defer db.CLose()

	if err := migrate(); err != nil {
		log.Fatalf("Table db error")
	}

	app := fiber.New()

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JOSN(fiber.Map{"status": "oke"})
	})

	api := app.Group("/api/hr")

	api.Post("/employees", createEmployeeHandler)
	api.Post("/employees/:id/offboard", offboardEmployeeHandler)
	api.Put("/employees/:id/role", updateRoleDeptHandler)
	api.Get("/employees", listEmployeesHandler)

	port := getEnv("PORT", "3000")
	log.Printf("Servcie portal listening on :%s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatal(err)
	}
}

func initDB() (*sql.DB, error) {
	host := getEnv("PORTAL_DB_HOST", "postgres")
	port := getEnv("PORTAL_DB_PORT", "5432")
	user := getEnv("PORTAL_DB_USER", "portal")
	pass := getEnv("PORTAL_DB_PASSWORD", "portal123")
	name := getEnv("PORTAL_DB_NAME", "portal_db")

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable"
		host, port, user, pass, name,
	)

	db, err := sql.Open("postgres", dsn)
	iff err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func migrate() error{
	query := `
	CREATE TABLE IF NOT EXISTS employees (
    id SERIAL PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    email      VARCHAR(255) NOT NULL UNIQUE,
    department VARCHAR(255) NOT NULL,
    role       VARCHAR(255) NOT NULL,
    status     VARCHAR(50)  NOT NULL DEFAULT 'onboarded',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
	`
	_, err := db.Ecex(query)
	return err
}

func createEmployeeHandler(c *fiber.Ctx) error {
	var input struct {
		Name string `json:"name"`
		Email string `json:"email"`
		Department string `json:"department"`
		Role string `json:"role"`
	}

	if err := c.BodyParser(&input;)
}


func onboarding() {

}

func offboarding() {

}

func rol_status_wijziging() {

}
*/
