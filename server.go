package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	graphql "github.com/graph-gophers/graphql-go"
	"github.com/graph-gophers/graphql-go/relay"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// TODO: Implement Input validation to make sure a valid URL was given.
const MAXATTEMPT = 5
const SHORTLEN = 7
const ALLOWEDCHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const PRELINKADDRESS = "https://iugo.tech/"
const TESTKEY = "testprivatekey"

// GraphQL
const schemaFile = "schema.graphql"

const apolloSandbox = `
<!DOCTYPE html>
<html lang="en">
<body style="margin: 0; overflow-x: hidden; overflow-y: hidden">
<div id="sandbox" style="height:100vh; width:100vw;"></div>
<script src="https://embeddable-sandbox.cdn.apollographql.com/_latest/embeddable-sandbox.umd.production.min.js"></script>
<script>
new window.EmbeddedSandbox({
  target: "#sandbox",
  initialEndpoint: "http://localhost:80/query",
});
</script>
</body>
 
</html>
`

func enableApolloSandbox(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(apolloSandbox))
}

// END GraphQL
type linkData struct {
	Link string `json:"link"`
}

type Controller struct {
	l     *log.Logger
	logic Logic
}

type SimpleLogic struct {
	l  *log.Logger
	db DataBase
}

type DataBaseWrapper struct {
	gormDB *gorm.DB
}

type DataBase interface {
	createUrlRow(*UrlDuo) error
	getUrlRowByShortUrl(string) (*UrlDuo, error)
	updateUrlDuo(*UrlDuo) error
	getAllUrlDuos(int) (*[]UrlDuo, error)
	createUser(*User) error
	getUserById(uint) (*User, error)
	getUserByIdWithUrlDuos(uint) (*User, error)
	getUserByEmail(string) (*User, error)
}

type Logic interface {
	generateShortLink(uint, string) (string, error)
	getLongLink(string) (string, error)
	updateShortLink(uint, string, string) error
	createUser(string, string, string) (uint, error)
	getUser(uint) (*User, error)
	getUserWithUrlDuos(uint) (*User, error)
	loginUser(string, string) (string, error)
}

type UrlDuo struct {
	ShortUrl   string     `gorm:"short_url"`
	LongUrl    string     `gorm:"long_url"`
	ExpireDate *time.Time `gorm:"expire_date"`
	UserID     uint
} // sql.NullTime

type User struct {
	gorm.Model
	Username   string `gorm:"username"`
	HashedPass string `gorm:"hashed_pass"`
	Email      string `gorm:"email"`
	UrlDuos    []UrlDuo
}

type UserForm struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UserView struct {
	ID       uint     `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	UrlDuos  []UrlDuo `json:"urlDuos"`
}

type contextKey int

const (
	userIDKey contextKey = iota
)

func main() {
	// Dependency Injection
	l := log.Default()
	db := DataBaseWrapper{gormDB: initDB()}
	logic := SimpleLogic{
		l:  l,
		db: db,
	}
	c := Controller{
		l:     l,
		logic: logic,
	}
	s, err := os.ReadFile(schemaFile)
	if err != nil {
		log.Fatal("GraphQL schema file couldn't be read!")
	}
	gqlLogic := GqlLogic{
		l:  l,
		db: db,
	}
	schema := graphql.MustParseSchema(string(s), &gqlLogic)
	if err != nil {
		fmt.Println(err.Error())
	}

	// Routing
	r := chi.NewRouter()
	r.Get("/{urlParam}", c.getLongLink)
	r.Post("/", AuthMiddleWare(http.HandlerFunc(c.generateShortLink)))
	r.Put("/{urlParam}", AuthMiddleWare(http.HandlerFunc(c.updateShortLink)))
	r.Get("/user/{urlParam}", AuthMiddleWare(http.HandlerFunc(c.getUser)))
	r.Post("/user", c.createUser)
	r.Post("/login", c.loginUser)
	r.Handle("/query", AuthMiddleWare(&relay.Handler{Schema: schema}))
	r.Get("/sandbox", http.HandlerFunc(enableApolloSandbox))
	http.ListenAndServe(":80", r)
}

// TODO: Cut down parameters for "Logic" methods (e.g. Use string only param for getLongLink(shortURL string))
func (logic SimpleLogic) generateShortLink(userID uint, longLink string) (string, error) {
	shortLink := calculateShortLink(longLink)
	expireDate := time.Now().Add(time.Hour * 1).UTC()
	urlRow := UrlDuo{
		ShortUrl:   shortLink,
		LongUrl:    longLink,
		ExpireDate: &expireDate,
		UserID:     userID,
	}
	err := logic.db.createUrlRow(&urlRow)
	if err != nil {
		return "", errors.New("failed to save to db")
	}
	return urlRow.ShortUrl, nil
}

func calculateShortLink(longLink string) string {
	linkSlice := make([]byte, SHORTLEN)
	for k := range linkSlice {
		linkSlice[k] = ALLOWEDCHARS[rand.Intn(len(ALLOWEDCHARS))]
	}
	return string(linkSlice)
}

func (logic SimpleLogic) getLongLink(shortLink string) (string, error) {
	urlRow, err := logic.db.getUrlRowByShortUrl(shortLink)
	if err != nil {
		logic.l.Println("Short URL not found in database for:", shortLink)
		return "", errors.New("associated long link not found")
	}
	return urlRow.LongUrl, nil
}

func (logic SimpleLogic) updateShortLink(userID uint, shortLink string, longLink string) error {
	u, err := logic.db.getUrlRowByShortUrl(shortLink)
	if err != nil {
		return err
	}
	if u.UserID != userID {
		return errors.New("unauthorized")
	}
	u.LongUrl = longLink
	err = logic.db.updateUrlDuo(u)
	if err != nil {
		return err
	}
	return nil
}

func (logic SimpleLogic) createUser(username string, email string, password string) (uint, error) {
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logic.l.Println("Failed password generation: " + err.Error())
		return 0, err
	}
	if username == "" || email == "" || password == "" {
		return 0, errors.New("username, email and password are required")
	}
	user := User{
		Username:   username,
		Email:      email,
		HashedPass: string(passHash),
	}
	err = logic.db.createUser(&user)
	if err != nil {
		return 0, err
	}
	return user.ID, nil
}

func (logic SimpleLogic) getUser(id uint) (*User, error) {
	user, err := logic.db.getUserById(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (logic SimpleLogic) getUserWithUrlDuos(id uint) (*User, error) {
	user, err := logic.db.getUserByIdWithUrlDuos(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (logic SimpleLogic) loginUser(email string, password string) (string, error) {
	user, err := logic.db.getUserByEmail(email)
	if err != nil {
		return "", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.HashedPass), []byte(password)); err != nil {
		return "", err
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"iss":    "url-shortener",
			"sub":    user.Email,
			"sub_id": user.ID,
			"exp":    jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		})
	s, err := t.SignedString([]byte(TESTKEY))
	if err != nil {
		return "", err
	}
	return s, nil
}

func (dbw DataBaseWrapper) createUrlRow(urlRow *UrlDuo) error {
	result := dbw.gormDB.Create(urlRow)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (dbw DataBaseWrapper) getUrlRowByShortUrl(shortUrl string) (*UrlDuo, error) {
	var urlRow UrlDuo
	result := dbw.gormDB.Where("short_url = ?", shortUrl).First(&urlRow)
	if result.Error != nil {
		return nil, result.Error
	}
	return &urlRow, nil
}

func (dbw DataBaseWrapper) updateUrlDuo(urlRow *UrlDuo) error {
	// dbw.gormDB.First(urlRow, urlRow.ShortUrl)
	result := dbw.gormDB.Where("short_url = ?", urlRow.ShortUrl).Save(urlRow)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (dbw DataBaseWrapper) getAllUrlDuos(last int) (*[]UrlDuo, error) {
	if last < -1 {
		return nil, errors.New("invalid number for last query")
	}
	var urlDuoSlice []UrlDuo
	result := dbw.gormDB.Limit(last).Find(&urlDuoSlice)
	if result.Error != nil {
		return nil, result.Error
	}
	return &urlDuoSlice, nil
}

func (dbw DataBaseWrapper) createUser(u *User) error {
	result := dbw.gormDB.Create(u)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (dbw DataBaseWrapper) getUserById(id uint) (*User, error) {
	var u User
	result := dbw.gormDB.Where("id = ?", id).First(&u)
	if result.Error != nil {
		return nil, result.Error
	}
	return &u, nil
}

func (dbw DataBaseWrapper) getUserByIdWithUrlDuos(id uint) (*User, error) {
	var u User
	result := dbw.gormDB.Preload("UrlDuos").Where("id = ?", id).First(&u)
	if result.Error != nil {
		return nil, result.Error
	}
	return &u, nil
}

func (dbw DataBaseWrapper) getUserByEmail(email string) (*User, error) {
	var u User
	result := dbw.gormDB.Where("email = ?", email).First(&u)
	if result.Error != nil {
		return nil, result.Error
	}
	return &u, nil
}

func (c Controller) generateShortLink(w http.ResponseWriter, r *http.Request) {
	requestUserID, ok := r.Context().Value(userIDKey).(int)
	if !ok {
		http.Error(w, "unexpected error", http.StatusInternalServerError)
		return
	}
	c.l.Printf("UrlDuo update request - by user ID:" + strconv.Itoa(requestUserID))
	var l linkData
	err := json.NewDecoder(r.Body).Decode(&l)
	if err != nil || len(l.Link) == 0 {
		http.Error(w, "Wrong format: Send JSON with 'link' attribute", http.StatusBadRequest)
		return
	}
	shortLink, err := c.logic.generateShortLink(uint(requestUserID), l.Link)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(PRELINKADDRESS + shortLink))
}

func (c Controller) getLongLink(w http.ResponseWriter, r *http.Request) {
	c.l.Printf("Long link request - by:" + r.UserAgent())
	shortLink := chi.URLParam(r, "urlParam")
	longLink, err := c.logic.getLongLink(shortLink)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Write([]byte(longLink))
}

func (c Controller) updateShortLink(w http.ResponseWriter, r *http.Request) { //TEST
	requestUserID, ok := r.Context().Value(userIDKey).(int)
	if !ok {
		http.Error(w, "unexpected error", http.StatusInternalServerError)
		return
	}
	c.l.Printf("UrlDuo update request - by user ID:" + strconv.Itoa(requestUserID))
	var l linkData
	shortLink := chi.URLParam(r, "urlParam")
	err := json.NewDecoder(r.Body).Decode(&l)
	if err != nil || len(l.Link) == 0 {
		http.Error(w, "Wrong format: Send JSON with 'link' attribute", http.StatusBadRequest)
		return
	}
	err = c.logic.updateShortLink(uint(requestUserID), shortLink, l.Link)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("UrlDuo updated"))
}

func (c Controller) getUser(w http.ResponseWriter, r *http.Request) {
	requestUserID, ok := r.Context().Value(userIDKey).(int)
	if !ok {
		http.Error(w, "unexpected error", http.StatusInternalServerError)
		return
	}
	c.l.Printf("User request - by user ID:" + strconv.Itoa(requestUserID))
	id := chi.URLParam(r, "urlParam")
	userID, err := strconv.Atoi(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := c.logic.getUserWithUrlDuos(uint(userID)) // u, err := c.logic.getUser(uint(userID))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	uView := u.ToUserView()
	json.NewEncoder(w).Encode(uView)
}

func (c Controller) createUser(w http.ResponseWriter, r *http.Request) {
	c.l.Printf("Create user request - by:" + r.UserAgent())
	var u UserForm
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil || len(u.Username) == 0 || len(u.Email) == 0 || len(u.Password) == 0 {
		http.Error(w, "Wrong format: Send JSON with 'username', 'email' and 'password' attributes", http.StatusBadRequest)
		return
	}
	id, err := c.logic.createUser(u.Username, u.Email, u.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte("User created with ID: " + strconv.Itoa(int(id))))
}

func (c Controller) loginUser(w http.ResponseWriter, r *http.Request) {
	c.l.Printf("Login user request - by:" + r.UserAgent())
	var u UserForm
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil || len(u.Email) == 0 || len(u.Password) == 0 {
		http.Error(w, "Wrong format: Send JSON with 'email' and 'password' attributes", http.StatusBadRequest)
		return
	}
	token, err := c.logic.loginUser(u.Email, u.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	response := map[string]interface{}{
		"token":      token,
		"expires_in": 3600,
		"token_type": "Bearer",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (u User) ToUserView() UserView {
	return UserView{
		ID:       u.ID,
		Username: u.Username,
		Email:    u.Email,
		UrlDuos:  u.UrlDuos,
	}
}

func AuthMiddleWare(next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		var b, tokenString string
		_, err := fmt.Sscan(authHeader, &b, &tokenString)
		if err != nil {
			http.Error(w, "Invalid Bearer", http.StatusUnauthorized)
			return
		}
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(TESTKEY), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid Token", http.StatusNonAuthoritativeInfo)
			return
		}
		exp, err := claims.GetExpirationTime()
		if err != nil {
			http.Error(w, "Invalid Token", http.StatusNonAuthoritativeInfo)
			return
		}
		if exp.Unix() < jwt.NewNumericDate(time.Now()).Unix() {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return

		}
		userID, ok := claims["sub_id"].(float64)
		if !ok {
			http.Error(w, "Unexpected Error", http.StatusInternalServerError)
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, userIDKey, int(userID))
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
