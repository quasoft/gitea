package sso

import (
	"reflect"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"gitea.com/macaron/macaron"
)

var (
	ssoMethods []SingleSignOn
)

// Methods returns the instances of all registered SSO methods
func Methods() []SingleSignOn {
	return ssoMethods
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
