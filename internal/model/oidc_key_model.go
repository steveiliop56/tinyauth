package model

type OIDCKey struct {
	ID         int    `gorm:"column:id;primaryKey;autoIncrement"`
	PrivateKey string `gorm:"column:private_key;not null"`
	CreatedAt  int64  `gorm:"column:created_at"`
	UpdatedAt  int64  `gorm:"column:updated_at"`
}

func (OIDCKey) TableName() string {
	return "oidc_keys"
}

