package service

import "github.com/steveiliop56/tinyauth/internal/config"

type LabelProvider interface {
	GetLabels(appDomain string) (config.App, error)
}
