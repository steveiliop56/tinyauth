package model

type Session struct {
	UUID        string `gorm:"column:uuid;primaryKey"`
	Username    string `gorm:"column:username"`
	Email       string `gorm:"column:email"`
	Name        string `gorm:"column:name"`
	Provider    string `gorm:"column:provider"`
	TOTPPending bool   `gorm:"column:totp_pending"`
	OAuthGroups string `gorm:"column:oauth_groups"`
	Expiry      int64  `gorm:"column:expiry"`
	OAuthName   string `gorm:"column:oauth_name"`
	OAuthSub    string `gorm:"column:oauth_sub"`
}
