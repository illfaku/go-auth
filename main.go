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
	"github.com/illfaku/go-auth/tinode"
	"github.com/illfaku/go-auth/token"
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

	r.POST("/register", func(c *gin.Context) {
		user := c.PostForm("username")
		pass := c.PostForm("password")
		_, err := accounts.CreateLocal(c.Request.Context(), model.Client, user, pass)
		if err != nil {
			c.JSON(model.Fail(http.StatusBadRequest, err.Error()))
			return
		}
		c.JSON(http.StatusOK, struct{}{})
	})

	r.POST("/login", token.Login(accounts, refreshTokens, jws))
	r.POST("/refresh", token.Refresh(accounts, refreshTokens, jws))

	r.POST("/tinode", tinode.Handle(accounts, jws))

	test := r.Group("/test")
	test.Use(func(c *gin.Context) {
		header := strings.Split(c.GetHeader("Authorization"), "Bearer ")
		if len(header) < 2 {
			c.JSON(model.Fail(http.StatusUnauthorized, "no Bearer token in Authorization header"))
			c.Abort()
			return
		}
		claims := new(model.AccessClaims)
		err := jws.Verify(header[1], claims)
		if err != nil {
			c.JSON(model.Fail(http.StatusUnauthorized, err.Error()))
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

func newDb() *mongo.Database {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGODB_CONNECTION_STRING")))
	if err != nil {
		panic(err)
	}
	return client.Database("main")
}
