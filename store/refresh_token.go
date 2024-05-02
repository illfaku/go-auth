package store

import (
	"context"

	"github.com/illfaku/go-auth/model"
	"github.com/illfaku/go-mongostore"
	"go.mongodb.org/mongo-driver/mongo"
)

type RefreshTokenStore struct {
	store *mongostore.Store[model.RefreshTokenData]
}

func NewRefreshTokenStore(collection *mongo.Collection) *RefreshTokenStore {
	return &RefreshTokenStore{mongostore.New[model.RefreshTokenData](collection)}
}

func (tokens *RefreshTokenStore) Create(ctx context.Context, accountId string) *model.RefreshToken {
	document := tokens.store.Create(ctx, &model.RefreshTokenData{AccountId: accountId})
	return &model.RefreshToken{Id: document.Key, Date: document.Updated, RefreshTokenData: document.Value}
}

func (tokens *RefreshTokenStore) Remove(ctx context.Context, id string) *model.RefreshTokenData {
	document := tokens.store.Remove(ctx, id)
	if document == nil {
		return nil
	}
	return &document.Value
}
