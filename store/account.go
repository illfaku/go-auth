package store

import (
	"context"

	"github.com/illfaku/go-auth/model"
	"github.com/illfaku/go-mongostore"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type AccountStore struct {
	store *mongostore.Store[model.AccountData]
}

func NewAccountStore(collection *mongo.Collection) *AccountStore {
	return &AccountStore{mongostore.New[model.AccountData](collection)}
}

func (accounts *AccountStore) Get(ctx context.Context, id string) *model.Account {
	document := accounts.store.Get(ctx, id)
	if document == nil {
		return nil
	}
	return &model.Account{Id: document.Key, AccountData: document.Value}
}

func (accounts *AccountStore) CreateLocal(
	ctx context.Context,
	role model.Role,
	user string,
	pass string,
) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	account := &model.AccountData{
		Role:  role,
		Kind:  model.LocalAccount,
		Local: model.LocalAccountData{Username: user, Password: hashed},
	}
	return accounts.store.Create(ctx, account).Key, nil
}

func (accounts *AccountStore) FindLocal(ctx context.Context, user string, pass string) *model.Account {
	filter := mongostore.Filter{"value.kind": model.LocalAccount, "value.local.username": user}
	document := accounts.store.Find(ctx, filter)
	if document == nil || bcrypt.CompareHashAndPassword(document.Value.Local.Password, []byte(pass)) != nil {
		return nil
	}
	return &model.Account{Id: document.Key, AccountData: document.Value}
}
