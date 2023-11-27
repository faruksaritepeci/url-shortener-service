package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	graphql "github.com/graph-gophers/graphql-go"
	"github.com/graph-gophers/graphql-go/relay"
	"gorm.io/gorm"
)

// TODO: Implement Input validation to make sure a valid URL was given.
const MAXATTEMPT = 5
const SHORTLEN = 7
const ALLOWEDCHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const PRELINKADDRESS = "https://iugo.tech/"

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
	getAllUrlDuos(int) (*[]UrlDuo, error)
}

type Logic interface {
	generateShortLink(string) (string, error)
	getLongLink(string) (string, error)
}

type UrlDuo struct {
	ShortUrl   string     `gorm:"short_url"`
	LongUrl    string     `gorm:"long_url"`
	ExpireDate *time.Time `gorm:"expire_date"`
} // sql.NullTime

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
	r.Post("/", c.generateShortLink)
	r.Handle("/query", &relay.Handler{Schema: schema})
	r.Get("/sandbox", http.HandlerFunc(enableApolloSandbox))
	http.ListenAndServe(":80", r)
}

// TODO: Cut down parameters for "Logic" methods (e.g. Use string only param for getLongLink(shortURL string))
func (logic SimpleLogic) generateShortLink(longLink string) (string, error) {
	shortLink := calculateShortLink(longLink)
	expireDate := time.Now().Add(time.Hour * 1).UTC()
	urlRow := UrlDuo{
		ShortUrl:   shortLink,
		LongUrl:    longLink,
		ExpireDate: &expireDate,
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

func (c Controller) generateShortLink(w http.ResponseWriter, r *http.Request) {
	c.l.Printf("Short link request - by:" + r.UserAgent())
	var l linkData
	err := json.NewDecoder(r.Body).Decode(&l)
	if err != nil || len(l.Link) == 0 {
		http.Error(w, "Wrong format: Send JSON with 'link' attribute", http.StatusBadRequest)
		return
	}
	shortLink, err := c.logic.generateShortLink(l.Link)
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
