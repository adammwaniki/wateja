//services/user/cmd/migrate/main.go
package main

import (
	"log"
	"os"

	mysqlCfg "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/adammwaniki/wateja/services/user/internal/store"
)

func main() {
	// Set up the DB config from environment variables for the migration database
	cfg := mysqlCfg.Config{
		User:                 os.Getenv("DB_USER"),
		Passwd:               os.Getenv("DB_PASSWORD"),
		Addr:                 os.Getenv("DB_ADDRESS"),
		DBName:               os.Getenv("DB_NAME"),
		Net:                  "tcp",
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	// Create a raw DB connection used by the migration tool
	db, err := store.NewRawDB(cfg)
	if err != nil {
		log.Fatal("failed to connect to db: ", err)
	}

	// Create a migration-compatible database instance
	driver, err := mysql.WithInstance(db, &mysql.Config{})
	if err != nil {
		log.Fatal("failed to get db instance: ", err)
	}

	// Initialize migration tool with source URL for migration scripts and the DB instance
	m, err := migrate.NewWithDatabaseInstance(
		"file://cmd/migrate/migrations",	// Path to the migration files
		"mysql",							// Database type
		driver,								// Database instance for migrations
	)
	if err != nil {
		log.Fatal("failed to create migration instance: ", err)
	}

	// Handle migration commands: 'up' for applying migrations, 'down' for rolling back
	cmd := os.Args[len(os.Args)-1]
	switch cmd {
	case "up":
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			log.Fatal(err)
		}
	case "down":
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown command: %s (expected 'up' or 'down')", cmd)
	}
}
