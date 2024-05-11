package model

type Account struct {
	Id string
	AccountData
}

type AccountData struct {
	Role  Role
	Kind  AccountKind
	Local LocalAccountData `bson:",omitempty"`
	Vk    VkAccountData    `bson:",omitempty"`
	Chat  ChatData         `bson:",omitempty"`
}

type AccountKind string

const (
	LocalAccount AccountKind = "local"
	VkAccount    AccountKind = "vk"
)

type LocalAccountData struct {
	Username string
	Password []byte
}

func (d LocalAccountData) IsZero() bool {
	return d.Username == "" && len(d.Password) == 0
}

type VkAccountData struct {
	UserId string `bson:"user_id"`
}

func (d VkAccountData) IsZero() bool {
	return d.UserId == ""
}

type ChatData struct {
	Uid string
}

func (d ChatData) IsZero() bool {
	return d.Uid == ""
}
