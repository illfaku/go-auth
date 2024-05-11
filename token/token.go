package token

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/illfaku/go-auth/model"
	"github.com/illfaku/go-auth/store"
	"github.com/illfaku/go-jws"
)

type TokenSet struct {
	Access    string    `json:"access_token"`
	Chat      []byte    `json:"chat_token"`
	Refresh   string    `json:"refresh_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

const (
	accessTtl  time.Duration = 10 * time.Minute
	refreshTtl time.Duration = 30 * 24 * time.Hour
)

func Login(accountStore *store.AccountStore, refreshStore *store.RefreshTokenStore, jws *jws.Jws) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.PostForm("username")
		pass := c.PostForm("password")
		account := accountStore.FindLocal(c.Request.Context(), user, pass)
		if account == nil {
			c.JSON(model.Fail(http.StatusUnauthorized, "username or password is invalid"))
			return
		}
		tokens := makeTokenSet(c.Request.Context(), refreshStore, jws, account)
		c.JSON(http.StatusOK, tokens)
	}
}

func Refresh(accountStore *store.AccountStore, refreshStore *store.RefreshTokenStore, jws *jws.Jws) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.PostForm("refresh_token")
		claims := new(model.RefreshClaims)
		err := jws.Verify(token, claims)
		if err != nil {
			c.JSON(model.Fail(http.StatusUnauthorized, err.Error()))
			return
		}
		refresh := refreshStore.Remove(c.Request.Context(), claims.ID)
		if refresh == nil {
			c.JSON(model.Fail(http.StatusUnauthorized, "unknown refresh token"))
			return
		}
		account := accountStore.Get(c.Request.Context(), refresh.AccountId)
		tokens := makeTokenSet(c.Request.Context(), refreshStore, jws, account)
		c.JSON(http.StatusOK, tokens)
	}
}

func makeTokenSet(
	ctx context.Context,
	refreshStore *store.RefreshTokenStore,
	jws *jws.Jws,
	account *model.Account,
) *TokenSet {
	refresh := refreshStore.Create(ctx, account.Id)
	accessClaims := &model.AccessClaims{
		Role: account.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   account.Id,
			ExpiresAt: jwt.NewNumericDate(refresh.Date.Add(accessTtl)),
		}}
	refreshClaims := &model.RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        refresh.Id,
			ExpiresAt: jwt.NewNumericDate(refresh.Date.Add(refreshTtl)),
		},
	}
	accessToken := jws.Sign(accessClaims)
	return &TokenSet{
		Access:    accessToken,
		Chat:      []byte(accessToken),
		Refresh:   jws.Sign(refreshClaims),
		ExpiresAt: accessClaims.ExpiresAt.Time,
	}
}
