package model

type OIDCAuthorizationCode struct {
	Code        string `gorm:"column:code;primaryKey"`
	ClientID    string `gorm:"column:client_id;not null"`
	RedirectURI string `gorm:"column:redirect_uri;not null"`
	Used        bool   `gorm:"column:used;default:false"`
	ExpiresAt   int64  `gorm:"column:expires_at;not null"`
	CreatedAt   int64  `gorm:"column:created_at;not null"`
}

func (OIDCAuthorizationCode) TableName() string {
	return "oidc_authorization_codes"
}

