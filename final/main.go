package main

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	_ "modernc.org/sqlite"
)

type TransferReq struct {
	FromID int `json:"from_id"`
	ToID   int `json:"to_id"`
	Amount int `json:"amount"`
}

func main() {
	db, err := sql.Open("sqlite", "./test.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		panic(err)
	}

	initLogger()
	r := gin.Default()
	r.Use(JSONLogger())

	r.GET("/accounts", func(c *gin.Context) {
		accounts, err := readAccounts(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"accounts": accounts})
	})

	r.POST("/transfer", func(c *gin.Context) {
		req := TransferReq{FromID: 1, ToID: 2, Amount: 500}
		if c.Request.ContentLength != 0 {
			if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid transfer request"})
				return
			}
		}
		if req.Amount <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "amount must be positive"})
			return
		}
		if req.FromID == req.ToID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "from_id and to_id must differ"})
			return
		}

		if err := transfer(db, req.FromID, req.ToID, req.Amount); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		accounts, err := readAccounts(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":  "transfer committed",
			"accounts": accounts,
		})
	})

	r.Run(":8080")
}

func initDB(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			balance INTEGER NOT NULL
		);`,
		`DELETE FROM accounts;`,
		`INSERT INTO accounts (balance) VALUES (1000), (1000);`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func transfer(db *sql.DB, fromID, toID, amount int) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var balance int
	if err := tx.QueryRow("SELECT balance FROM accounts WHERE id = ?", fromID).Scan(&balance); err != nil {
		return err
	}
	if balance < amount {
		return errors.New("insufficient balance")
	}

	if _, err := tx.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, fromID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, toID); err != nil {
		return err
	}

	return tx.Commit()
}

func readAccounts(db *sql.DB) ([]gin.H, error) {
	rows, err := db.Query("SELECT id, balance FROM accounts ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []gin.H
	for rows.Next() {
		var id, balance int
		if err := rows.Scan(&id, &balance); err != nil {
			return nil, err
		}
		accounts = append(accounts, gin.H{
			"id":      id,
			"balance": balance,
		})
	}

	return accounts, rows.Err()
}

// curl http://localhost:8080/accounts
// curl -X POST http://localhost:8080/transfer -H "Content-Type: application/json" -d "{\"from_id\":1,\"to_id\":2,\"amount\":500}"

func initLogger() {
	os.MkdirAll("logs", 0755)
	log.SetFormatter(&log.JSONFormatter{})
	log.SetOutput(&lumberjack.Logger{
		Filename:   "./logs/api-v1.log",
		MaxSize:    1,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	})
}

func JSONLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.WithFields(log.Fields{
			"ip":     c.ClientIP(),
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"query":  c.Request.URL.RawQuery,
			"header": c.Request.Header,
		}).Info("incoming request")
		c.Next()
	}
}
