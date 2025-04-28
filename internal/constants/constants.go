package constants

// TinyauthLabels is a list of labels that can be used in a tinyauth protected container
var TinyauthLabels = []string{
	"tinyauth.oauth.whitelist",
	"tinyauth.users",
	"tinyauth.allowed",
	"tinyauth.headers",
	"tinyauth.oauth.groups",
}

// Claims are the OIDC supported claims (including preferd username for some reason)
type Claims struct {
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}
