package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	_ "github.com/lib/pq"
)

var (
	keycloakURL   = os.Getenv("KEYCLOAK_URL")
	keycloakRealm = os.Getenv("KEYCLOAK_REALM")
	keycloakAdmin = os.Getenv("KEYCLOAK_ADMIN")
	keycloakPass  = os.Getenv("KEYCLOAK_ADMIN_PASSWORD")

	store = session.New()
)

/* hardcoded RBAC
type AppUser struct {
	Email    string
	Password string
	Role     string
}

var users = map[string]AppUser{
	"employee@example.com": {
		Email:    "employee@example.com",
		Password: "Employee123!",
		Role:     "employee",
	},

	"hr@example.com": {
		Email:    "hr@example.com",
		Password: "Hr123!",
		Role:     "HR",
	},

	"it@example.com": {
		Email:    "it@example.com",
		Password: "It123!",
		Role:     "IT",
	},
}
*/

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

	app.Get("/", requireRole("employee", "HR", "IT"), func(c *fiber.Ctx) error {
		return c.SendFile("ui/index.html")
	})

	//offboarding frontend naar backend
	app.Get("/offboard", requireRole("HR", "IT"), func(c *fiber.Ctx) error {
		return c.SendFile("ui/offboard.html")
	})

	app.Get("/change-role", requireRole("HR", "IT"), func(c *fiber.Ctx) error {
		return c.SendFile("ui/change_role.html")
	})

	app.Get("/password-reset", requireRole("employee", "HR", "IT"), func(c *fiber.Ctx) error {
		return c.SendFile("ui/password_reset.html")
	})

	app.Get("/register-device", requireRole("employee", "HR", "IT"), func(c *fiber.Ctx) error {
		return c.SendFile("ui/register_device.html")
	})

	app.Get("/login", func(c *fiber.Ctx) error {
		return c.SendFile("ui/login.html")
	})

	// frontend naar backend onboarding
	app.Get("/onboard", requireRole("HR", "IT"), func(c *fiber.Ctx) error {
		return c.SendFile("ui/onboard.html")
	})

	// login
	app.Post("/login", func(c *fiber.Ctx) error {
		type LoginBody struct {
			Email    string `form:"email"`
			Password string `form:"password"`
		}

		var body LoginBody
		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).SendString("Invalid login body")
		}

		roles, err := loginWithKeycloak(body.Email, body.Password)
		if err != nil {
			log.Println("login error:", err)
			return c.Status(401).SendString("Invalid Keycloak Login")
		}

		if len(roles) == 0 {
			return c.Status(403).SendString("No roles assigned")
		}

		sess, _ := store.Get(c)
		sess.Set("email", body.Email)
		sess.Set("roles", roles)
		sess.Save()

		return c.Redirect("/")
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

	//offbaording
	app.Post("/offboard", func(c *fiber.Ctx) error {
		var body struct {
			Email string `json:"email" form:"email"`
		}

		if err := c.BodyParser(&body); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid body"})
		}

		if body.Email == "" {
			return c.Status(400).JSON(fiber.Map{"error": "missing email"})
		}

		//Database status naar inactive
		_, err := db.Exec(`UPDATE employees SET status='inactive' WHERE email=$1`, body.Email)
		if err != nil {
			log.Println("db error:", err)
			return c.Status(500).JSON(fiber.Map{"error": "db update error"})
		}

		//Keycloak
		token, err := getKeycloakAdminToken()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "token error"})
		}

		userID, err := getKeycloakUserID(token, body.Email)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "user lookup error"})
		}

		err = disableKeycloakUser(token, userID)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "keycloak diable error"})
		}

		return c.JSON(fiber.Map{
			"message": "employee offboarded",
			"email":   body.Email,
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

	// 201 = created, 409 = bestaat al
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keycloak create user error: %s - %s", resp.Status, string(body))
	}

	return nil
}

// User ID ophalen
func getKeycloakUserID(token, email string) (string, error) {
	endpoint := fmt.Sprintf("%s/admin/realms/%s/users?email=%s", keycloakURL, keycloakRealm, url.QueryEscape(email))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("lookup error: %s - %s", resp.Status, string(b))
	}

	var arr []struct {
		ID string `json:"id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&arr); err != nil {
		return "", err
	}

	if len(arr) == 0 {
		return "", fmt.Errorf("user not found")
	}

	return arr[0].ID, nil
}

// Keycloak user uitschakelen

func disableKeycloakUser(token, userID string) error {
	endpoint := fmt.Sprintf("%s/admin/realms/%s/users/%s", keycloakURL, keycloakRealm, userID)

	payload := bytes.NewBuffer([]byte(`{"enabled": false}`))

	req, err := http.NewRequest("PUT", endpoint, payload)
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

	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("disable error: %s - %s", resp.Status, string(b))
	}

	return nil
}

//RBAC

func loginWithKeycloak(email, password string) ([]string, error) {
	data := url.Values{}
	data.Set("client_id", "admin-cli")
	data.Set("grant_type", "password")
	data.Set("username", email)
	data.Set("password", password)
	data.Set("scope", "openid email profile")

	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, keycloakRealm)
	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failed: %s", string(body))
	}

	var tokenRes struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenRes); err != nil {
		return nil, err
	}

	roles, err := extractRolesFromJWT(tokenRes.AccessToken)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

func extractRolesFromJWT(token string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payloadPart := parts[1]

	// Base64URL decoden (zonder padding)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// realm_access: { "roles": ["IT", "HR", ...] }
	ra, ok := payload["realm_access"].(map[string]interface{})
	if !ok {
		return []string{}, nil
	}

	rolesRaw, ok := ra["roles"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	roles := []string{}
	for _, r := range rolesRaw {
		if s, ok := r.(string); ok {
			roles = append(roles, s)
		}
	}

	return roles, nil
}

/*

func getKeycloakUserInfo(token string) ([]string, error) {
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", keycloakURL, keycloakRealm)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	realmAcces, ok := data["realm_access"].(map[string]interface{})
	if !ok {
		return []string{}, nil
	}

	rolesRaw, ok := realmAcces["roles"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	roles := []string{}
	for _, r := range rolesRaw {
		if s, ok := r.(string); ok {
			roles = append(roles, s)
		}
	}

	return roles, nil

}

*/

func requireRole(allowedRoles ...string) fiber.Handler {
	allowedMap := make(map[string]bool)
	for _, r := range allowedRoles {
		allowedMap[r] = true
	}

	return func(c *fiber.Ctx) error {
		sess, _ := store.Get(c)
		rolesVal := sess.Get("roles")
		if rolesVal == nil {
			return c.Redirect("/login")
		}

		roles, ok := rolesVal.([]string)
		if !ok {
			return c.Status(403).SendString("Forbidden")
		}

		for _, r := range roles {
			if allowedMap[r] {
				return c.Next()
			}
		}

		return c.Status(403).SendString("Forbidden")
	}
}

/* Voor SSO
	oidcIssuerURL = os.Getenv("OIDC_ISSUER_URL")
	oidcClientID = os.Getenv("OIDC_CLIENT_ID")
	oidcClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	oidcRedirectURL = os.Getenv("OIDC_REDIRECT_URL")

	publicBaseURL = os.Getenv("PUBLIC_BASE_URL")
	sessionSecret = []byte(os.Getenv("SESSION_SECRET"))

	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
)

type UserSession struct {
	Subject string `json:"sub"`
	Email string `json:"email"`
	Roles []string `json:"roles"`
}
*/

/* Hardcoded rbac functie =
func getCurrentUser(c *fiber.Ctx) *AppUser {
sess, err := store.Get(c)
if err != nil {
return nil
 }

 emailVal := sess.Get("email")
 if emailVal == nil {
  return nil
  }

  email, ok := emailVal.(string)
  if !ok || email == "" {
  return nil
   }

   u, ok := users[email]
   if !ok { return nil } return &u }
*/
