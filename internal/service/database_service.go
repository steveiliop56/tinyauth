package service

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/steveiliop56/tinyauth/internal/assets"

	"github.com/glebarez/sqlite"
	"github.com/golang-migrate/migrate/v4"
	sqliteMigrate "github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"
)

type DatabaseServiceConfig struct {
	DatabasePath string
}

type DatabaseService struct {
	config   DatabaseServiceConfig
	database *gorm.DB
}

func NewDatabaseService(config DatabaseServiceConfig) *DatabaseService {
	return &DatabaseService{
		config: config,
	}
}

func (ds *DatabaseService) Init() error {
	dbPath := ds.config.DatabasePath
	if dbPath == "" {
		dbPath = "/data/tinyauth.db"
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create database directory %s: %w", dir, err)
	}

	gormDB, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})

	if err != nil {
		return err
	}

	sqlDB, err := gormDB.DB()

	if err != nil {
		return err
	}

	sqlDB.SetMaxOpenConns(1)

	err = ds.migrateDatabase(sqlDB)

	if err != nil && err != migrate.ErrNoChange {
		return err
	}

	ds.database = gormDB
	return nil
}

func (ds *DatabaseService) migrateDatabase(sqlDB *sql.DB) error {
	data, err := iofs.New(assets.Migrations, "migrations")

	if err != nil {
		return err
	}

	target, err := sqliteMigrate.WithInstance(sqlDB, &sqliteMigrate.Config{})

	if err != nil {
		return err
	}

	migrator, err := migrate.NewWithInstance("iofs", data, "tinyauth", target)

	if err != nil {
		return err
	}

	return migrator.Up()
}

func (ds *DatabaseService) GetDatabase() *gorm.DB {
	return ds.database
}
