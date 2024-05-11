package model

import "github.com/golang-jwt/jwt/v5"

type AccessClaims struct {
	Role    Role   `json:"role"`
	ChatUid string `json:"chat_uid,omitempty"`
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	jwt.RegisteredClaims
}
