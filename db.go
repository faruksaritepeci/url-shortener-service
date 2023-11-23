package main

import (
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func initDB() *gorm.DB {
	dbURL, err := os.ReadFile("db.env")
	if err != nil {
		fmt.Println("DB connection failed. Exiting...")
		os.Exit(1)
	}

	db, err := gorm.Open(postgres.Open(string(dbURL)), &gorm.Config{})
	if err != nil {
		fmt.Println("DB connection failed. Exiting...")
		os.Exit(1)
	}
	return db
}
