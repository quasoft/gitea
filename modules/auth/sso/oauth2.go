package sso

import (
	"strings"
	"time"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/timeutil"

	"gitea.com/macaron/macaron"
	"gitea.com/macaron/session"
)

// CheckOAuthAccessToken returns uid of user from oauth token
func CheckOAuthAccessToken(accessToken string) int64 {
	// JWT tokens require a "."
	if !strings.Contains(accessToken, ".") {
		return 0
	}
	token, err := models.ParseOAuth2Token(accessToken)
	if err != nil {
		log.Trace("ParseOAuth2Token: %v", err)
		return 0
	}
	var grant *models.OAuth2Grant
	if grant, err = models.GetOAuth2GrantByID(token.GrantID); err != nil || grant == nil {
		return 0
	}
	if token.Type != models.TypeAccessToken {
		return 0
	}
	if token.ExpiresAt < time.Now().Unix() || token.IssuedAt > time.Now().Unix() {
		return 0
	}
	return grant.UserID
}

// OAuth2 implements the SingleSignOn interface and authenticates requests
// (API requests only) by looking for an OAuth token in query parameters or the
// "Authorization" header.
type OAuth2 struct {
}

// Init does nothing as the OAuth2 implementation does not need to allocate any resources
func (o *OAuth2) Init() error {
	return nil
}

// Free does nothing as the OAuth2 implementation does not have to release any resources
func (o *OAuth2) Free() error {
	return nil
}

// userIDFromToken returns the user id corresponding to the OAuth token.
func (o *OAuth2) userIDFromToken(ctx *macaron.Context) int64 {
	// Check access token.
	tokenSHA := ctx.Query("token")
	if len(tokenSHA) == 0 {
		tokenSHA = ctx.Query("access_token")
	}
	if len(tokenSHA) == 0 {
		// Well, check with header again.
		auHead := ctx.Req.Header.Get("Authorization")
		if len(auHead) > 0 {
			auths := strings.Fields(auHead)
			if len(auths) == 2 && (auths[0] == "token" || strings.ToLower(auths[0]) == "bearer") {
				tokenSHA = auths[1]
			}
		}
	}
	if len(tokenSHA) == 0 {
		return 0
	}

	// Let's see if token is valid.
	if strings.Contains(tokenSHA, ".") {
		uid := CheckOAuthAccessToken(tokenSHA)
		if uid != 0 {
			ctx.Data["IsApiToken"] = true
		}
		return uid
	}
	t, err := models.GetAccessTokenBySHA(tokenSHA)
	if err != nil {
		if models.IsErrAccessTokenNotExist(err) || models.IsErrAccessTokenEmpty(err) {
			log.Error("GetAccessTokenBySHA: %v", err)
		}
		return 0
	}
	t.UpdatedUnix = timeutil.TimeStampNow()
	if err = models.UpdateAccessToken(t); err != nil {
		log.Error("UpdateAccessToken: %v", err)
	}
	ctx.Data["IsApiToken"] = true
	return t.UID
}

// IsEnabled returns true as this plugin is enabled by default and its not possible
// to disable it from settings.
func (o *OAuth2) IsEnabled() bool {
	return true
}

// Priority determines the order in which authentication methods are executed.
// The lower the priority, the sooner the plugin is executed.
// The OAuth2 plugin should be executed first as it must ignore the user id stored
// in the session (if there is a user id stored in session other plugins might
// return the user object for that id).
func (o *OAuth2) Priority() int {
	return 10000
}

// VerifyAuthData extracts the user ID from the OAuth token in the query parameters
// or the "Authorization" header and returns the corresponding user object for that ID.
// If verification is successful returns an existing user object.
// Returns nil if verification fails.
func (o *OAuth2) VerifyAuthData(ctx *macaron.Context, sess session.Store) *models.User {
	if !models.HasEngine {
		return nil
	}

	if !isAPIPath(ctx.Req.URL.Path) {
		return nil
	}

	id := o.userIDFromToken(ctx)
	if id <= 0 {
		return nil
	}

	user, err := models.GetUserByID(id)
	if err != nil {
		if !models.IsErrUserNotExist(err) {
			log.Error("GetUserByName: %v", err)
		}
		return nil
	}

	return user
}

// init registers the plugin to the list of available SSO methods
func init() {
	Register(&OAuth2{})
}
