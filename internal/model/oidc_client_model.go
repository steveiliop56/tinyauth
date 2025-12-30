package model

type OIDCClient struct {
	ClientID     string `gorm:"column:client_id;primaryKey"`
	ClientSecret string `gorm:"column:client_secret"`
	ClientName   string `gorm:"column:client_name"`
	RedirectURIs string `gorm:"column:redirect_uris"` // JSON array
	GrantTypes   string `gorm:"column:grant_types"`   // JSON array
	ResponseTypes string `gorm:"column:response_types"` // JSON array
	Scopes       string `gorm:"column:scopes"`         // JSON array
	CreatedAt    int64  `gorm:"column:created_at"`
	UpdatedAt    int64  `gorm:"column:updated_at"`
}

func (OIDCClient) TableName() string {
	return "oidc_clients"
}

