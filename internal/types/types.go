package types

type LoginQuery struct {
	RedirectURI string `url:"redirect_uri"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	Username string
	Password string
}

type UserList struct {
	Users []User
}

type Config struct {
	Port int `validate:"number" mapstructure:"port"`
	Address string `mapstructure:"address, ip4_addr"`
	Secret string `validate:"required,len=32" mapstructure:"secret"`
	RootURL string `validate:"required,url" mapstructure:"root-url"`
	AppURL string `validate:"required,url" mapstructure:"app-url"`
	Users string `validate:"required" mapstructure:"users"`
}

type UserContext struct {
	Username string
	IsLoggedIn bool
}