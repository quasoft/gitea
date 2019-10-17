package sso

import (
	"net/http"
	"strings"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/modules/base"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"

	"gitea.com/macaron/macaron"
	"gitea.com/macaron/session"
	"github.com/quasoft/websspi"
	gouuid "github.com/satori/go.uuid"
)

var (
	// sspiAuth is a global instance of the websspi authentication package,
	// which is used to avoid acquiring the server credential handle on
	// every request
	sspiAuth *websspi.Authenticator
)

// SSPI implements the SingleSignOn interface and authenticates requests
// via the built-in SSPI module in Windows for SPNEGO authentication.
// On successful authentication returns a valid user object.
// Returns nil if authentication fails.
type SSPI struct {
}

// Init creates a new global websspi.Authenticator object
func (s *SSPI) Init() error {
	config := websspi.NewConfig()
	var err error
	sspiAuth, err = websspi.New(config)
	return err
}

// Free releases resources used by the global websspi.Authenticator object
func (s *SSPI) Free() error {
	return sspiAuth.Free()
}

// IsEnabled checks if EnableSSPI setting is true
func (s *SSPI) IsEnabled() bool {
	return setting.Service.EnableSSPI
}

// Priority determines the order in which authentication methods are executed.
// The lower the priority, the sooner the plugin is executed.
// The SSPI plugin should be executed last as it returns 401 status code
// if negotiation fails or should continue, which would prevent other
// authentication methods to execute at all.
func (s *SSPI) Priority() int {
	return 50000
}

// VerifyAuthData uses SSPI (Windows implementation of SPNEGO) to authenticate the request.
// If authentication is successful, returs the corresponding user object.
// If negotiation should continue or authentication fails, immediately returns a 401 HTTP
// response code, as required by the SPNEGO protocol.
func (s *SSPI) VerifyAuthData(ctx *macaron.Context, sess session.Store) *models.User {
	// If user has requested to temporary suppress single sign-on verification,
	// skip all SSO plugins
	if Suppressed(ctx) == "1" {
		return nil
	}

	userInfo, outToken, err := sspiAuth.Authenticate(ctx.Req.Request, ctx.Resp)
	if err != nil {
		log.Warn("Authentication failed with error: %v\n", err)
		sspiAuth.AppendAuthenticateHeader(ctx.Resp, outToken)
		if s.isHomePage(ctx) {
			// Do not error with 401 code on home page
			return nil
		}
		ctx.Status(http.StatusUnauthorized)
		return nil
	}
	if outToken != "" {
		sspiAuth.AppendAuthenticateHeader(ctx.Resp, outToken)
	}

	newSep := setting.Service.SSPISeparatorReplacement
	username := strings.ReplaceAll(userInfo.Username, "\\", newSep)
	username = strings.ReplaceAll(username, "/", newSep)
	username = strings.ReplaceAll(username, "@", newSep)
	log.Info("Authenticated as %s\n", username)
	if len(username) == 0 {
		return nil
	}

	user, err := models.GetUserByName(username)
	if err != nil {
		if models.IsErrUserNotExist(err) && setting.Service.SSPIAutoCreateUsers {
			return s.newUser(ctx, username)
		}
		log.Error("GetUserByName: %v", err)
		return nil
	}

	// Make sure requests to API paths and PWA resources do not create a new session
	if !isAPIPath(ctx.Req.URL.Path) && !isPWAResource(ctx.Req.URL.Path) {
		handleSignIn(ctx, sess, user)
	}

	return user
}

func (s *SSPI) isHomePage(ctx *macaron.Context) bool {
	currentURL := setting.AppSubURL + strings.TrimSuffix(ctx.Req.URL.EscapedPath(), "/")
	return currentURL == strings.TrimSuffix(setting.AppSubURL, "/")
}

// newUser creates a new user object for the purpose of automatic registration
// and populates its name and email with the information present in request headers.
func (s *SSPI) newUser(ctx *macaron.Context, username string) *models.User {
	email := gouuid.NewV4().String() + "@example.org"
	user := &models.User{
		Name:                         username,
		Email:                        email,
		KeepEmailPrivate:             true,
		Passwd:                       gouuid.NewV4().String(),
		IsActive:                     setting.Service.SSPIAutoActivateUsers,
		Language:                     setting.Service.SSPIDefaultLang,
		UseCustomAvatar:              true,
		Avatar:                       base.DefaultAvatarLink(),
		EmailNotificationsPreference: models.EmailNotificationsDisabled,
	}
	if err := models.CreateUser(user); err != nil {
		// FIXME: should I create a system notice?
		log.Error("CreateUser: %v", err)
		return nil
	}
	return user
}

// init registers the plugin to the list of available SSO methods
func init() {
	Register(&SSPI{})
}
