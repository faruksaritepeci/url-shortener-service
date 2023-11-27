package main

import (
	"context"
	"errors"
	"log"
	"time"

	graphql "github.com/graph-gophers/graphql-go"
)

type GqlLogic struct {
	l  *log.Logger
	db DataBase
}

func (g GqlLogic) Hello() string {
	return "Hello"
}

func (g GqlLogic) AllUrlDuos(ctx context.Context, args struct{ Last *int32 }) ([]UrlDuoResolver, error) {
	if args.Last != nil && *args.Last < 0 {
		return []UrlDuoResolver{{}}, errors.New("invalid last argument (must be non-negative)")
	}
	if args.Last == nil {
		var allValues int32 = -1
		args.Last = &allValues
	}
	urlDuos, err := g.db.getAllUrlDuos(int(*args.Last))
	if err != nil {
		return []UrlDuoResolver{{}}, err
	}
	urlDuoResolvers := NewUrlDuoResolverSlice(*urlDuos)
	return urlDuoResolvers, nil
}

func (g GqlLogic) UrlDuo(ctx context.Context, args struct{ ShortUrl graphql.ID }) (*UrlDuoResolver, error) {
	shortLink := string(args.ShortUrl)
	urlDuo, err := g.db.getUrlRowByShortUrl(shortLink)
	if err != nil {
		g.l.Println("Short URL not found in database for:", shortLink)
		return nil, errors.New("associated long link not found")
	}
	return &UrlDuoResolver{u: urlDuo}, nil
}

func (g GqlLogic) CreateUrlDuo(ctx context.Context, args struct{ LongUrl string }) (UrlDuoResolver, error) {
	longLink := args.LongUrl
	if longLink == "" {
		return UrlDuoResolver{}, errors.New("longUrl cannot be empty string")
	}
	shortLink := calculateShortLink(longLink)
	expireDate := time.Now().Add(time.Hour * 1).UTC()
	urlRow := UrlDuo{
		ShortUrl:   shortLink,
		LongUrl:    longLink,
		ExpireDate: &expireDate,
	}
	err := g.db.createUrlRow(&urlRow)
	if err != nil {
		return UrlDuoResolver{}, errors.New("failed to save to db")
	}
	return UrlDuoResolver{u: &urlRow}, nil
}

type GraphQLLogic interface {
	Hello() string
	AllUrlDuos(args struct{ Last *int }) []UrlDuoResolver
}

// UrlDuoResolver
type UrlDuoResolver struct {
	u *UrlDuo
}

func (r UrlDuoResolver) Short() graphql.ID {
	return graphql.ID(r.u.ShortUrl)
}

func (r UrlDuoResolver) Long() string {
	return r.u.LongUrl
}

func (r UrlDuoResolver) Expiry() *string {
	if r.u.ExpireDate == nil {
		return nil
	}
	expiry := r.u.ExpireDate.String()
	return &expiry
}

func NewUrlDuoResolver(u *UrlDuo) UrlDuoResolver {
	return UrlDuoResolver{u: u}
}

func NewUrlDuoResolverSlice(us []UrlDuo) []UrlDuoResolver {
	resolverSlice := make([]UrlDuoResolver, len(us))
	for k, v := range us {
		currentUrlDuo := v // avoid pointing to same address.
		resolverSlice[k] = UrlDuoResolver{u: &currentUrlDuo}
	}
	return resolverSlice
}
