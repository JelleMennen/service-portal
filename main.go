package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gofiber/fiber/v2"
	_ "github.com/lib/pq"
)

var (
	keycloakURL   = os.Getenv("KEYCLOAK_URL")
	keycloakRealm = os.Getenv("KEYCLOAK_REALM")
	keycloakAdmin = os.Getenv("KEYCLOAK_ADMIN")
	keycloakPass  = os.Getenv("KEYCLOAK_ADMIN_PASSWORD")
)

func main() {
	// kijkt of het in de env staat
	if keycloakURL == "" {
		keycloakURL = "http://keycloak:8080"
	}
	if keycloakRealm == "" {
		keycloakRealm = "master"
	}

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

	//
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendFile("ui/onboard.html")
	})

	// onboard functie
	app.Post("/onboard", func(c *fiber.Ctx) error {
		var body struct {
			Name       string `json:"name" form:"name"`
			Email      string `json:"email" form:"email"`
			Department string `json:"department" form:"department"`
			Role       string `json:"role" form:"role"`
		}

		if err := c.BodyParser(&body); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
		}

		if body.Name == "" || body.Email == "" || body.Department == "" || body.Role == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing fields"})
		}

		// in de database plaatsen

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

		// User in keycloak aanmaken
		token, err := getKeycloakAdminToken()
		if err != nil {
			log.Println("keycloak token error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token error"})
		}

		if err := createKeycloakUser(token, body.Email); err != nil {
			log.Println("keycloak create user error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "keycloak user error"})
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

// token ophalen
func getKeycloakAdminToken() (string, error) {
	if keycloakURL == "" || keycloakAdmin == "" || keycloakPass == "" {
		return "", fmt.Errorf("keycloak env vars niet gezet")
	}

	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, keycloakRealm)

	data := url.Values{}
	data.Set("client_id", "admin-cli")
	data.Set("username", keycloakAdmin)
	data.Set("password", keycloakPass)
	data.Set("grant_type", "password")

	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keycloak token error : %s - %s", resp.Status, string(body))
	}

	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("geen access_token in keycloak response")
	}

	return tr.AccessToken, nil
}

type keycloakCredential struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Temporary bool   `json:"temporary"`
}

type keycloakUser struct {
	Username      string               `json:"username"`
	Email         string               `json:"email"`
	EmailVerified bool                 `json:"emailVerified"`
	Enabled       bool                 `json:"enabled"`
	Credentials   []keycloakCredential `json:"credentials"`
}

// user aanmaken
func createKeycloakUser(token string, email string) error {
	u := keycloakUser{
		Username:      email,
		Email:         email,
		EmailVerified: true,
		Enabled:       true,
		Credentials: []keycloakCredential{
			{
				Type:      "password",
				Value:     "Welcome123!",
				Temporary: true,
			},
		},
	}

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(u); err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/users", keycloakURL, keycloakRealm)
	req, err := http.NewRequest("POST", endpoint, buf)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 201 = created, 409 = bestaat al → voor nu ook ok
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keycloak create user error: %s - %s", resp.Status, string(body))
	}

	return nil
}
