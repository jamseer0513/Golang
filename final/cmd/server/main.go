package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

const authorizationCookieName = "authorization"

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"-"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type WithdrawAccountRequest struct {
	Password string `json:"password"`
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type LoginResponse struct {
	AuthMode string       `json:"auth_mode"`
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
}

type PostView struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	OwnerID     uint   `json:"owner_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type CreatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type UpdatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type PostListResponse struct {
	Posts []PostView `json:"posts"`
}

type PostResponse struct {
	Post PostView `json:"post"`
}

type DepositRequest struct {
	Amount int64 `json:"amount"`
}

type BalanceWithdrawRequest struct {
	Amount int64 `json:"amount"`
}

type TransferRequest struct {
	ToUsername string `json:"to_username"`
	Amount     int64  `json:"amount"`
}

type Store struct {
	db *sql.DB
}

type SessionStore struct {
	tokens map[string]User
}

func main() {
	store, err := openStore("./app.db", "./schema.sql", "./seed.sql")
	if err != nil {
		panic(err)
	}
	defer store.close()

	sessions := newSessionStore()

	router := gin.Default()
	registerStaticRoutes(router)

	auth := router.Group("/api/auth")
	{
		//회원가입
		auth.POST("/register", func(c *gin.Context) {
			var request RegisterRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid register request"})
				return
			}
			//공백확인
			if request.Username == "" || request.Name == "" || request.Email == "" || request.Phone == "" || request.Password == "" {
				c.JSON(http.StatusBadRequest, gin.H{"message": "특정 값이 없습니다."})
				return
			}

			//사용자ID 중복확인
			_, ok, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if ok {
				c.JSON(http.StatusBadRequest, gin.H{"message": "중복된 사용자ID."})
				return
			}

			//insert in DB
			_, err = store.db.Exec(`
				INSERT INTO users (username, name, email, phone, password, balance, is_admin)
				VALUES (?, ?, ?, ?, ?, 0, 0)
			`, request.Username, request.Name, request.Email, request.Phone, request.Password)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "DB 저장실패."})
				return
			}
			//응답콘솔
			c.JSON(http.StatusAccepted, gin.H{
				"user": gin.H{
					"username": request.Username,
					"name":     request.Name,
					"email":    request.Email,
					"phone":    request.Phone,
				},
			})
		})

		auth.POST("/login", func(c *gin.Context) {
			var request LoginRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid login request"})
				return
			}

			user, ok, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if !ok || user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid credentials"})
				return
			}

			token, err := sessions.create(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create session"})
				return
			}

			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(authorizationCookieName, token, 60*60*8, "/", "", false, true)
			c.JSON(http.StatusOK, LoginResponse{
				AuthMode: "header-and-cookie",
				Token:    token,
				User:     makeUserResponse(user),
			})
		})

		auth.POST("/logout", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{
				"message": "logout complete!",
			})
		})

		//내정보-회원탈퇴
		auth.POST("/withdraw", func(c *gin.Context) {
			var request WithdrawAccountRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			//DB에 delete
			_, err = store.db.Exec(`
				DELETE FROM users
				WHERE Password = ?;
			`, request.Password)

			//응답콘솔
			c.JSON(http.StatusAccepted, gin.H{
				"message": "회원탈퇴 완료.",
				"user":    makeUserResponse(user),
			})
		})
	}

	protected := router.Group("/api")
	{
		protected.GET("/me", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user": makeUserResponse(user)})
		})

		//입금
		protected.POST("/banking/deposit", func(c *gin.Context) {
			var request DepositRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid deposit request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "입금액이 음수."})
				return
			}

			//DB에 insert
			_, err = store.db.Exec(`
				UPDATE users SET balance = balance + ? 
				where id = ?
			`, request.Amount, user.ID)

			//세션 업데이트
			user.Balance += request.Amount
			sessions.update(token, user)

			c.JSON(http.StatusOK, gin.H{
				"message": "입금 완료.",
				"user":    makeUserResponse(user),
				"amount":  request.Amount,
			})
		})
		//출금
		protected.POST("/banking/withdraw", func(c *gin.Context) {
			var request BalanceWithdrawRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if request.Amount > user.Balance {
				c.JSON(http.StatusBadRequest, gin.H{"message": "자신의 계좌보다 많은 금액을 출금."})
				return
			}

			//DB에 insert
			_, err = store.db.Exec(`
				UPDATE users SET balance = balance - ?
				where id = ?
			`, request.Amount, user.ID)

			//세션 업데이트
			user.Balance -= request.Amount
			sessions.update(token, user)

			c.JSON(http.StatusOK, gin.H{
				"message": "출금 완료.",
				"todo":    "replace with balance check and decrement query",
				"user":    makeUserResponse(user),
				"amount":  request.Amount,
			})
		})
		//송금
		protected.POST("/banking/transfer", func(c *gin.Context) {
			var request TransferRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid transfer request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			//상대방 조회
			_, ok, err := store.findUserByUsername(request.ToUsername)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "상대방 조회 실패"})
				return
			}
			if !ok {
				c.JSON(http.StatusBadRequest, gin.H{"message": "존재하지 않는 상대방."})
				return
			}
			if request.ToUsername == user.Username {
				c.JSON(http.StatusBadRequest, gin.H{"message": "자기 자신에게 송금X."})
				return
			}

			//잔액 확인
			if user.Balance < request.Amount {
				c.JSON(http.StatusBadRequest, gin.H{"message": "잔액이 부족합니다."})
				return
			}

			//나의 송금
			_, err = store.db.Exec(`
				UPDATE users SET balance = balance - ?
				where id = ?
			`, request.Amount, user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "송금 실패"})
				return
			}

			//상대방 입금
			_, err = store.db.Exec(`
				UPDATE users SET balance = balance + ?
				where username = ?
			`, request.Amount, request.ToUsername)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "입금 실패"})
				return
			}

			// 세션 업데이트
			user.Balance -= request.Amount
			sessions.update(token, user)

			c.JSON(http.StatusOK, gin.H{
				"message": "송금 완료.",
				"user":    makeUserResponse(user),
				"target":  request.ToUsername,
				"amount":  request.Amount,
			})
		})

		//게시글 목록-게시글 목록
		protected.GET("/posts", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "DB 조회실패."})
				return
			}

			//DB내에서 post 모두 조회
			rows, err := store.db.Query(`
				SELECT posts.id, posts.title, posts.content, posts.owner_id, users.name, users.email, posts.created_at, posts.updated_at
				FROM posts
				JOIN users ON posts.owner_id = users.id
			`)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "DB 조회실패."})
				return
			}
			defer rows.Close()

			// 콘솔출력
			posts := []PostView{}
			for rows.Next() {
				var p PostView
				if err := rows.Scan(&p.ID, &p.Title, &p.Content, &p.OwnerID, &p.Author, &p.AuthorEmail, &p.CreatedAt, &p.UpdatedAt); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "DB 파싱실패."})
					return
				}
				posts = append(posts, p)
			}

			c.JSON(http.StatusOK, PostListResponse{Posts: posts})
		})

		//글 작성
		protected.POST("/posts", func(c *gin.Context) {
			var request CreatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid create request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			now := time.Now().Format(time.RFC3339)
			_, err = store.db.Exec(`
				INSERT INTO posts (title, content, owner_id, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?)
			`, request.Title, request.Content, user.ID, now, now)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "DB 저장실패."})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "글 작성완료.",
				"post": PostView{
					ID:          1,
					Title:       strings.TrimSpace(request.Title),
					Content:     strings.TrimSpace(request.Content),
					OwnerID:     user.ID,
					Author:      user.Name,
					AuthorEmail: user.Email,
					CreatedAt:   now,
					UpdatedAt:   now,
				},
			})
		})

		//글 상세-상세 응답 and 게시글 목록-선택한 게시글
		protected.GET("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			id := c.Param("id")

			var p PostView
			err := store.db.QueryRow(`
				SELECT posts.id, posts.title, posts.content, posts.owner_id, users.name, users.email, posts.created_at, posts.updated_at
				FROM posts
				JOIN users ON posts.owner_id = users.id
				WHERE posts.id = ?
			`, id).Scan(&p.ID, &p.Title, &p.Content, &p.OwnerID, &p.Author, &p.AuthorEmail, &p.CreatedAt, &p.UpdatedAt)
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"message": "게시글을 찾을 수 없습니다."})
				return
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "DB 조회실패."})
				return
			}

			c.JSON(http.StatusOK, PostResponse{Post: p})
		})

		//글 상세-변경요청-수정
		protected.PUT("/posts/:id", func(c *gin.Context) {
			var request UpdatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid update request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			id := c.Param("id")
			now := time.Now().Format(time.RFC3339)

			var result sql.Result
			if user.IsAdmin {
				result, err = store.db.Exec(`
					UPDATE posts SET title = ?, content = ?, updated_at = ?
					WHERE id = ?
				`, strings.TrimSpace(request.Title), strings.TrimSpace(request.Content), now, id)
			} else {
				result, err = store.db.Exec(`
					UPDATE posts SET title = ?, content = ?, updated_at = ?
					WHERE id = ? AND owner_id = ?
				`, strings.TrimSpace(request.Title), strings.TrimSpace(request.Content), now, id, user.ID)
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "DB 수정실패."})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusForbidden, gin.H{"message": "수정 권한이 없거나 존재하지 않는 게시글입니다."})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "글 수정완료.",
				"post": PostView{
					Title:       strings.TrimSpace(request.Title),
					Content:     strings.TrimSpace(request.Content),
					OwnerID:     user.ID,
					Author:      user.Name,
					AuthorEmail: user.Email,
					UpdatedAt:   now,
				},
			})
		})

		//글 상세-변경요청-삭제
		protected.DELETE("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			id := c.Param("id")

			var result sql.Result
			if user.IsAdmin {
				result, err = store.db.Exec(`
					DELETE FROM posts WHERE id = ?
				`, id)
			} else {
				result, err = store.db.Exec(`
					DELETE FROM posts WHERE id = ? AND owner_id = ?
				`, id, user.ID)
			}
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "DB 삭제실패."})
				return
			}

			affected, _ := result.RowsAffected()
			if affected == 0 {
				c.JSON(http.StatusForbidden, gin.H{"message": "삭제 권한이 없거나 존재하지 않는 게시글입니다."})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "글 삭제완료."})
		})
	}

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

func openStore(databasePath, schemaFile, seedFile string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initialize(schemaFile, seedFile); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) close() error {
	return s.db.Close()
}

func (s *Store) initialize(schemaFile, seedFile string) error {
	if err := s.execSQLFile(schemaFile); err != nil {
		return err
	}
	if err := s.execSQLFile(seedFile); err != nil {
		return err
	}
	return nil
}

func (s *Store) execSQLFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(string(content))
	return err
}

func (s *Store) findUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`
		SELECT id, username, name, email, phone, password, balance, is_admin
		FROM users
		WHERE username = ?
	`, strings.TrimSpace(username))

	var user User
	var isAdmin int64
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	user.IsAdmin = isAdmin == 1

	return user, true, nil
}

func newSessionStore() *SessionStore {
	return &SessionStore{
		tokens: make(map[string]User),
	}
}

func (s *SessionStore) create(user User) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}

	s.tokens[token] = user
	return token, nil
}

func (s *SessionStore) lookup(token string) (User, bool) {
	user, ok := s.tokens[token]
	return user, ok
}

// 세션 업데이트
func (s *SessionStore) update(token string, user User) {
	s.tokens[token] = user
}

func (s *SessionStore) delete(token string) {
	delete(s.tokens, token)
}

// fe 페이지 캐싱으로 테스트에 혼동이 있어, 별도 처리없이 main에 두시면 될 것 같습니다
// registerStaticRoutes 는 정적 파일(HTML, JS, CSS)을 제공하는 라우트를 등록한다.
func registerStaticRoutes(router *gin.Engine) {
	// 브라우저 캐시 비활성화 — 정적 파일과 루트 경로에만 적용
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})
	router.Static("/static", "./static")
	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
}

func makeUserResponse(user User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
		Phone:    user.Phone,
		Balance:  user.Balance,
		IsAdmin:  user.IsAdmin,
	}
}

func clearAuthorizationCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationCookieName, "", -1, "/", "", false, true)
}

func tokenFromRequest(c *gin.Context) string {
	headerValue := strings.TrimSpace(c.GetHeader("Authorization"))
	if headerValue != "" {
		return headerValue
	}

	cookieValue, err := c.Cookie(authorizationCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookieValue)
}

func newSessionToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
