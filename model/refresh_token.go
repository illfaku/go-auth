package model

import "time"

type RefreshToken struct {
	Id   string
	Date time.Time
	RefreshTokenData
}

type RefreshTokenData struct {
	AccountId string `bson:"account_id"`
}
