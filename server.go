package main

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
)

// TODO: Implement Input validation to make sure a valid URL was given.
const MAXATTEMPT = 5
const SHORTLEN = 7
const ALLOWEDCHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const PRELINKADDRESS = "https://iugo.tech/"

// In memory test

var linksMutex = sync.RWMutex{}
var links = map[string]string{}

type linkData struct {
	Link string `json:"link"`
}

func main() {
	r := chi.NewRouter()
	r.Get("/{urlParam}", getLongLink)
	r.Post("/", generateShortLink)
	http.ListenAndServe(":80", r)
}

func generateShortLink(w http.ResponseWriter, r *http.Request) {
	var l linkData
	err := json.NewDecoder(r.Body).Decode(&l)
	if err != nil {
		http.Error(w, "Wrong format: Send JSON with 'link' attribute", http.StatusBadRequest)
		return
	}
	shortLink := calculateShortLink(l.Link)
	linksMutex.Lock()
	defer linksMutex.Unlock()
	_, ok := links[shortLink]
	for counter := 0; ok; counter++ {
		shortLink = calculateShortLink(l.Link)
		_, ok = links[shortLink]
		if counter == MAXATTEMPT {
			http.Error(w, "Link failed to generate", http.StatusInternalServerError)
			return
		}
	}

	links[shortLink] = l.Link
	w.Write([]byte(PRELINKADDRESS + shortLink))
}

func calculateShortLink(longLink string) string {
	linkSlice := make([]byte, SHORTLEN)
	for k := range linkSlice {
		linkSlice[k] = ALLOWEDCHARS[rand.Intn(len(ALLOWEDCHARS))]
	}
	return string(linkSlice)
}

func getLongLink(w http.ResponseWriter, r *http.Request) {
	shortLink := chi.URLParam(r, "urlParam")
	longLink, ok := links[shortLink]
	if !ok {
		http.Error(w, "Given short URL doesn't exist.", http.StatusNotFound)
		return
	}
	w.Write([]byte(longLink))
}
