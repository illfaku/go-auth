package main

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/illfaku/go-auth/model"
	"github.com/illfaku/go-auth/store"
	"github.com/illfaku/go-jws"
)

type TokenPair struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}

type AccessClaims struct {
	Role string
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	jwt.RegisteredClaims
}

type TokenAuth struct {
	accountStore *store.AccountStore
	refreshStore *store.RefreshTokenStore
	jws          *jws.Jws
	accessTtl    time.Duration
	refreshTtl   time.Duration
}

type TokenOption func(*TokenAuth)

func NewTokenAuth(
	accountStore *store.AccountStore,
	refreshStore *store.RefreshTokenStore,
	jws *jws.Jws,
	opts ...TokenOption,
) *TokenAuth {
	auth := &TokenAuth{accountStore, refreshStore, jws, 10 * time.Minute, 30 * 24 * time.Hour}
	for _, opt := range opts {
		opt(auth)
	}
	return auth
}

func WithAccessTtl(ttl time.Duration) TokenOption {
	return func(auth *TokenAuth) { auth.accessTtl = ttl }
}

func WithRefreshTtl(ttl time.Duration) TokenOption {
	return func(auth *TokenAuth) { auth.refreshTtl = ttl }
}

func (auth *TokenAuth) MakeTokenPair(ctx context.Context, account *model.Account) *TokenPair {
	refresh := auth.refreshStore.Create(ctx, account.Id)
	return &TokenPair{
		Access:  auth.jws.Sign(newAccessClaims(account, refresh.Date, auth.accessTtl)),
		Refresh: auth.jws.Sign(newRefreshClaims(refresh.Id, refresh.Date, auth.refreshTtl)),
	}
}

func (auth *TokenAuth) RefreshTokenPair(ctx context.Context, tokenString string) (*TokenPair, error) {
	claims := new(RefreshClaims)
	err := auth.jws.Verify(tokenString, claims)
	if err != nil {
		return nil, err
	}
	data := auth.refreshStore.Remove(ctx, claims.ID)
	if data == nil {
		return nil, errors.New("unknown refresh token")
	}
	return auth.MakeTokenPair(ctx, auth.accountStore.Get(ctx, data.AccountId)), nil
}

func newAccessClaims(account *model.Account, issued time.Time, ttl time.Duration) *AccessClaims {
	return &AccessClaims{
		string(account.Role),
		jwt.RegisteredClaims{
			Subject:   account.Id,
			ExpiresAt: jwt.NewNumericDate(issued.Add(ttl)),
		},
	}
}

func newRefreshClaims(id string, issued time.Time, ttl time.Duration) *RefreshClaims {
	return &RefreshClaims{
		jwt.RegisteredClaims{
			ID:        id,
			ExpiresAt: jwt.NewNumericDate(issued.Add(ttl)),
		},
	}
}
