package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
)

var (
	keycloakURL   = os.Getenv("KEYCLOAK_URL")
	keycloakRealm = os.Getenv("KEYCLOAK_REALM")
	keycloakAdmin = os.Getenv("KEYCLOAK_ADMIN")
	keycloakPass  = os.Getenv("KEYCLOAK_ADMIN_PASSWORD")

	oidcIssuerURL    = os.Getenv("OIDC_ISSUER_URL")
	oidcClientID     = os.Getenv("OIDC_CLIENT_ID")
	oidcClientSecret = os.Getenv("OIDC_CLIENT_SECRET")
	oidcRedirectURL  = os.Getenv("OIDC_REDIRECT_URL")

	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config

	store = session.New()
)

/*(Hardcoded RBAC)
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

func randomState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

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

	initOIDC()

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

	app.Get("/it-admin", requireRole("IT"), func(c *fiber.Ctx) error {
		return c.SendFile("ui/it_admin.html")
	})

	app.Get("/login", func(c *fiber.Ctx) error {
		state := randomState()

		sess, _ := store.Get(c)
		sess.Set("oauth_state", state)
		if err := sess.Save(); err != nil {
			log.Println("session save eror:", err)
		}
		return c.Redirect(oauth2Config.AuthCodeURL(state))
	})

	app.Get("/logout", func(c *fiber.Ctx) error {
		sess, _ := store.Get(c)
		_ = sess.Destroy()
		return c.Redirect("/login")
	})

	app.Get("/callback", func(c *fiber.Ctx) error {
		//state checken
		sess, _ := store.Get(c)
		expected, _ := sess.Get("oauth_state").(string)
		got := c.Query("state")

		if expected == "" || got == "" || expected != got {
			return c.Status(401).SendString("invalid state")
		}
		sess.Delete("oauth_state")
		_ = sess.Save()

		// code exchange
		ctx := context.Background()

		code := c.Query("code")
		if code == "" {
			return c.Status(400).SendString("missing code")
		}

		tok, err := oauth2Config.Exchange(ctx, code)
		if err != nil {
			log.Println("token exchange error:", err)
			return c.Status(401).SendString("token exchange failed")
		}

		// ID check token
		rawIDToken, ok := tok.Extra("id_token").(string)
		if !ok || rawIDToken == "" {
			return c.Status(401).SendString("no id_token")
		}

		idToken, err := oidcVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			log.Println("id token verify error:", err)
			return c.Status(401).SendString("invalid id_token")
		}

		// Claims rollen uit Keycloak halen van de Realm
		var claims struct {
			Email             string `json:"email"`
			PreferredUsername string `json:"preferred_username"`
			RealmAccess       struct {
				Roles []string `json:"roles"`
			} `json:"realm_access"`
		}

		if err := idToken.Claims(&claims); err != nil {
			return c.Status(401).SendString("invalid claims")
		}

		email := claims.Email
		if email == "" {
			email = claims.PreferredUsername
		}

		// Session vullen
		sess, _ = store.Get(c)
		sess.Set("email", email)
		sess.Set("roles", claims.RealmAccess.Roles)
		if err := sess.Save(); err != nil {
			log.Println("session save error:", err)
		}

		return c.Redirect("/")
	})

	//onboarding
	app.Get("/onboard", requireRole("HR", "IT"), func(c *fiber.Ctx) error {
		return c.SendFile("ui/onboard.html")
	})

	app.Post("/onboard", requireRole("HR", "IT"), func(c *fiber.Ctx) error {
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
	app.Post("/offboard", requireRole("HR", "IT"), func(c *fiber.Ctx) error {
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

func initOIDC() {
	if oidcIssuerURL == "" || oidcClientID == "" || oidcClientSecret == "" || oidcRedirectURL == "" {
		log.Fatal("OIDC env vars niet correct gezet")
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, oidcIssuerURL)
	if err != nil {
		log.Fatalf("kan OIDC provider niet ophalen: %v", err)
	}

	oidcProvider = provider
	oidcVerifier = provider.Verifier(&oidc.Config{
		ClientID: oidcClientID,
	})

	oauth2Config = &oauth2.Config{
		ClientID:     oidcClientID,
		ClientSecret: oidcClientSecret,
		RedirectURL:  oidcRedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

//RBAC via Keycloak API aka de middelware voor de JWT token

type CurrentUser struct {
	Email string
	Roles []string
}

func getCurrentUser(c *fiber.Ctx) *CurrentUser {
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

	rolesVal := sess.Get("roles")
	roles := []string{}

	switch v := rolesVal.(type) {
	case []string:
		roles = v
	case []interface{}:
		for _, r := range v {
			if s, ok := r.(string); ok {
				roles = append(roles, s)
			}
		}

	}

	return &CurrentUser{Email: email, Roles: roles}
}

func requireRole(allowedRoles ...string) fiber.Handler {
	allowed := make(map[string]bool)
	for _, r := range allowedRoles {
		allowed[r] = true
	}

	return func(c *fiber.Ctx) error {
		user := getCurrentUser(c)
		if user == nil {
			return c.Redirect("/login")
		}

		for _, r := range user.Roles {
			if allowed[r] {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).SendString("403 Forbidden")
	}
}

//RBAC Hardcoded

/*

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
	if !ok {
		return nil
	}

	return &u
}

func requireRole(allowedRoles ...string) fiber.Handler {
	allowed := make(map[string]bool)
	for _, r := range allowedRoles {
		allowed[r] = true
	}

	return func(c *fiber.Ctx) error {
		user := getCurrentUser(c)
		if user == nil {
			return c.Redirect("/login")
		}

		if !allowed[user.Role] {
			return c.Status(fiber.StatusForbidden).SendString("403 Forbidden")
		}

		return c.Next()
	}
}
*/

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
