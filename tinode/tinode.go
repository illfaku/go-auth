package tinode

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/illfaku/go-auth/model"
	"github.com/illfaku/go-auth/store"
	"github.com/illfaku/go-jws"
)

type request struct {
	Endpoint string `json:"endpoint"`
	Name     string `json:"name"`
	Record   record `json:"rec,omitempty"`
	Secret   string `json:"secret,omitempty"`
}

type response struct {
	Err         string     `json:"err,omitempty"`
	Record      record     `json:"rec,omitempty"`
	ByteVal     string     `json:"byteval,omitempty"`
	TimeVal     time.Time  `json:"ts,omitempty"`
	BoolVal     bool       `json:"boolval,omitempty"`
	StrSliceVal []string   `json:"strarr,omitempty"`
	NewAcc      newAccount `json:"newacc,omitempty"`
}

type record struct {
	Uid        string        `json:"uid,omitempty"`
	AuthLevel  string        `json:"authlvl,omitempty"`
	Lifetime   time.Duration `json:"lifetime,omitempty"`
	Features   string        `json:"features,omitempty"`
	Tags       []string      `json:"tags,omitempty"`
	State      string        `json:"state,omitempty"`
	Credential string        `json:"cred,omitempty"`
}

type newAccount struct {
	Auth    string      `json:"auth,omitempty"`
	Anon    string      `json:"anon,omitempty"`
	Public  interface{} `json:"public,omitempty"`
	Trusted interface{} `json:"trusted,omitempty"`
	Private interface{} `json:"private,omitempty"`
}

func newRecord(uid string, role model.Role) record {
	return record{Uid: uid, AuthLevel: "auth", State: "ok", Features: "V", Tags: []string{fmt.Sprintf("role:%v", role)}}
}

func Handle(accounts *store.AccountStore, jws *jws.Jws) gin.HandlerFunc {

	respond := func(c *gin.Context, response *response) {
		c.JSON(http.StatusOK, response)
	}

	authenticate := func(
		c *gin.Context,
		req *request,
		basicFlow func(*model.Account),
		tokenFlow func(*model.AccessClaims),
	) {
		secretBytes, err := base64.StdEncoding.DecodeString(req.Secret)
		if err != nil {
			respond(c, &response{Err: "failed"})
			return
		}
		secret := string(secretBytes)
		if req.Name == "basic" {
			parts := strings.SplitN(secret, ":", 2)
			account := accounts.FindLocal(c.Request.Context(), parts[0], parts[1])
			if account == nil {
				respond(c, &response{Err: "failed"})
				return
			}
			basicFlow(account)
		} else {
			claims := new(model.AccessClaims)
			if jws.Verify(secret, claims) != nil {
				respond(c, &response{Err: "failed"})
				return
			}
			tokenFlow(claims)
		}
	}

	return func(c *gin.Context) {

		req := new(request)
		if err := c.ShouldBindJSON(req); err != nil {
			respond(c, &response{Err: "malformed"})
			return
		}

		switch req.Endpoint {
		case "auth":
			authenticate(
				c,
				req,
				func(account *model.Account) {
					if account.Chat.Uid != "" {
						respond(c, &response{Record: newRecord(account.Chat.Uid, account.Role)})
					} else {
						respond(c, &response{
							Record: newRecord("", account.Role),
							NewAcc: newAccount{Auth: "JRW", Anon: "N"},
						})
					}
				},
				func(claims *model.AccessClaims) {
					if claims.ChatUid != "" {
						respond(c, &response{Record: newRecord(claims.ChatUid, claims.Role)})
						return
					}
					account := accounts.Get(c.Request.Context(), claims.Subject)
					if account == nil {
						respond(c, &response{Err: "failed"})
						return
					}
					if account.Chat.Uid != "" {
						respond(c, &response{Record: newRecord(account.Chat.Uid, account.Role)})
					} else {
						respond(c, &response{
							Record: newRecord("", account.Role),
							NewAcc: newAccount{Auth: "JRW", Anon: "N"},
						})
					}
				},
			)
		case "link":
			authenticate(
				c,
				req,
				func(account *model.Account) {
					accounts.LinkChat(c.Request.Context(), account.Id, req.Record.Uid)
					respond(c, &response{})
				},
				func(claims *model.AccessClaims) {
					accounts.LinkChat(c.Request.Context(), claims.Subject, req.Record.Uid)
					respond(c, &response{})
				},
			)
		case "rtagns":
			respond(c, &response{StrSliceVal: []string{"role"}})
		default:
			respond(c, &response{Err: "unsupported"})
		}
	}
}
