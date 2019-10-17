package sso

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"

	"gitea.com/macaron/macaron"
	"gitea.com/macaron/session"
)

var (
	ssoMethods []SingleSignOn
)

// Methods returns the instances of all registered SSO methods
func Methods() []SingleSignOn {
	return ssoMethods
}

// MethodsByPriority returns the instances of all registered SSO methods, ordered by ascending priority
func MethodsByPriority() []SingleSignOn {
	methods := Methods()
	sort.Slice(methods, func(i, j int) bool {
		return methods[i].Priority() < methods[j].Priority()
	})
	return methods
}

// Register adds the specified instance to the list of available SSO methods
func Register(method SingleSignOn) {
	ssoMethods = append(ssoMethods, method)
}

// Init should be called exactly once when the application starts to allow SSO plugins
// to allocate necessary resources
func Init() {
	for _, method := range Methods() {
		if !method.IsEnabled() {
			continue
		}
		err := method.Init()
		if err != nil {
			log.Error("Could not initialize '%s' SSO method, error: %s", reflect.TypeOf(method).String(), err)
		}
	}
}

// Free should be called exactly once when the application is terminating to allow SSO plugins
// to release necessary resources
func Free() {
	for _, method := range Methods() {
		if !method.IsEnabled() {
			continue
		}
		err := method.Free()
		if err != nil {
			log.Error("Could not free '%s' SSO method, error: %s", reflect.TypeOf(method).String(), err)
		}
	}
}

// SessionUser returns the user object corresponding to the "uid" session variable.
func SessionUser(sess session.Store) *models.User {
	// Get user ID
	uid := sess.Get("uid")
	if uid == nil {
		return nil
	}
	id, ok := uid.(int64)
	if !ok {
		return nil
	}

	// Get user object
	user, err := models.GetUserByID(id)
	if err != nil {
		if !models.IsErrUserNotExist(err) {
			log.Error("GetUserById: %v", err)
		}
		return nil
	}
	return user
}

// UpdateSuppress checks if the user has requests to temporary deactivate SSO authentication
// (eg. in order to be able to use a local account) or to activate it again, and updates
// the setting.CookieSuppressSSO value.
func UpdateSuppress(ctx *macaron.Context) {
	newValue := ""
	if ctx.Req.FormValue("disable_sso") == "1" {
		newValue = "1"
	} else if ctx.Req.FormValue("enable_sso") == "1" {
		newValue = "0"
	}
	if newValue != "" {
		ctx.SetCookie(setting.CookieSuppressSSO, newValue, nil, setting.AppSubURL, setting.SessionConfig.Domain, setting.SessionConfig.Secure, true)
	}
}

// Suppressed returns "1" if the user has requested to temporary deactivate SSO authentication,
// returns "0" if the user has requested it to be activated again,
// or an empty string if neither was requested during the current session.
func Suppressed(ctx *macaron.Context) string {
	if ctx.Req.FormValue("disable_sso") == "1" {
		return "1"
	} else if ctx.Req.FormValue("enable_sso") == "1" {
		return "0"
	} else {
		return ctx.GetCookie(setting.CookieSuppressSSO)
	}
}

// isAPIPath returns true if the specified URL is an API path
func isAPIPath(url string) bool {
	return strings.HasPrefix(url, "/api/")
}

// isPWAResource checks if the url is the Web App Manifest file or the Service Worker script
func isPWAResource(url string) bool {
	return url == "/manifest.json" || url == "/serviceworker.js"
}

func handleSignIn(ctx *macaron.Context, sess session.Store, user *models.User) {
	_ = sess.Delete("openid_verified_uri")
	_ = sess.Delete("openid_signin_remember")
	_ = sess.Delete("openid_determined_email")
	_ = sess.Delete("openid_determined_username")
	_ = sess.Delete("twofaUid")
	_ = sess.Delete("twofaRemember")
	_ = sess.Delete("u2fChallenge")
	_ = sess.Delete("linkAccount")
	err := sess.Set("uid", user.ID)
	if err != nil {
		log.Error(fmt.Sprintf("Error setting session: %v", err))
	}
	err = sess.Set("uname", user.Name)
	if err != nil {
		log.Error(fmt.Sprintf("Error setting session: %v", err))
	}

	// Language setting of the user overwrites the one previously set
	// If the user does not have a locale set, we save the current one.
	if len(user.Language) == 0 {
		user.Language = ctx.Locale.Language()
		if err := models.UpdateUserCols(user, "language"); err != nil {
			log.Error(fmt.Sprintf("Error updating user language [user: %d, locale: %s]", user.ID, user.Language))
			return
		}
	}

	ctx.SetCookie("lang", user.Language, nil, setting.AppSubURL, setting.SessionConfig.Domain, setting.SessionConfig.Secure, true)

	// Clear whatever CSRF has right now, force to generate a new one
	ctx.SetCookie(setting.CSRFCookieName, "", -1, setting.AppSubURL, setting.SessionConfig.Domain, setting.SessionConfig.Secure, true)
}
