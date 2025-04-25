package constants

// TinyauthLabels is a list of labels that can be used in a tinyauth protected container
var TinyauthLabels = []string{
	"tinyauth.oauth.whitelist",
	"tinyauth.users",
	"tinyauth.allowed",
	"tinyauth.headers",
}

// Claims are the OIDC supported claims
type Claims struct {
	Name       string `json:"name"`
	FamilyName string `json:"family_name"`
	GivenName  string `json:"given_name"`
	MiddleName string `json:"middle_name"`
	Nickname   string `json:"nickname"`
	Picture    string `json:"picture"`
	Email      string `json:"email"`
}
