package main

import (
	"context"
	"encoding/hex"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/graceful"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/illfaku/go-auth/model"
	"github.com/illfaku/go-auth/store"
	"github.com/illfaku/go-jws"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	r, err := graceful.Default(graceful.WithAddr(":80"))
	if err != nil {
		panic(err)
	}
	defer r.Close()

	addRoutes(r)

	if err := r.RunWithContext(ctx); err != nil && err != context.Canceled {
		panic(err)
	}
}

func addRoutes(r *graceful.Graceful) {
	secret, err := hex.DecodeString(os.Getenv("JWS_SECRET"))
	if err != nil {
		panic(err)
	}
	jws := jws.New(jwt.SigningMethodHS256, secret)

	db := newDb()
	accounts := store.NewAccountStore(db.Collection("accounts"))
	refreshTokens := store.NewRefreshTokenStore(db.Collection("refresh_tokens"))

	auth := NewTokenAuth(accounts, refreshTokens, jws)

	r.POST("/register", func(c *gin.Context) {
		user := c.PostForm("username")
		pass := c.PostForm("password")
		id, err := accounts.CreateLocal(c.Request.Context(), model.Client, user, pass)
		if err != nil {
			fail(c, http.StatusBadRequest, err.Error())
			return
		}
		c.String(http.StatusOK, id)
	})

	r.POST("/login", func(c *gin.Context) {
		user := c.PostForm("username")
		pass := c.PostForm("password")
		account := accounts.FindLocal(c.Request.Context(), user, pass)
		if account == nil {
			fail(c, http.StatusUnauthorized, "username or password is invalid")
			return
		}
		c.JSON(http.StatusOK, auth.MakeTokenPair(c.Request.Context(), account))
	})

	r.POST("/refresh", func(c *gin.Context) {
		token := c.PostForm("refresh_token")
		result, err := auth.RefreshTokenPair(c.Request.Context(), token)
		if err != nil {
			fail(c, http.StatusUnauthorized, err.Error())
			return
		}
		c.JSON(http.StatusOK, result)
	})

	test := r.Group("/test")
	test.Use(func(c *gin.Context) {
		header := strings.Split(c.GetHeader("Authorization"), "Bearer ")
		if len(header) < 2 {
			fail(c, http.StatusUnauthorized, "no Bearer token in Authorization header")
			c.Abort()
			return
		}
		claims := new(AccessClaims)
		err := jws.Verify(header[1], claims)
		if err != nil {
			fail(c, http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Set("id", claims.Subject)
		c.Next()
	})
	test.GET("/id", func(c *gin.Context) {
		c.String(http.StatusOK, c.GetString("id"))
	})
}

func fail(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{"code": code, "message": message})
}

func newDb() *mongo.Database {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGODB_CONNECTION_STRING")))
	if err != nil {
		panic(err)
	}
	return client.Database("main")
}
