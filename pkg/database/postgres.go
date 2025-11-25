package database

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/lib/pq"
)

func ConnectPostgres() *sql.DB {
	conn := os.Getenv("POSTGRES_DSN") // example: postgres://user:pass@db:5432/hr?sslmode=disable

	db, err := sql.Open("postgres", conn)
	if err != nil {
		log.Fatal(err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to PostgreSQL")
	return db
}
