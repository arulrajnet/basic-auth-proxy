package session

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

var logger = log.GetLogger()

type SessionManager struct {
	store        *sessions.CookieStore
	cookieName   string
	cookiePath   string
	cookieDomain string
	maxAge       int
	secure       bool
	httpOnly     bool
	sameSite     http.SameSite
}

type UserInfo struct {
	Username string    `json:"username"`
	Password string    `json:"password"`
	LoggedIn time.Time `json:"logged_in"`
}

func NewSessionManager(secretKey string) *SessionManager {
	// Create a new secure cookie encoder
	hashKey := []byte(secretKey)
	if len(secretKey) < 32 {
		// Ensure hash key is at least 32 bytes
		hashKey = securecookie.GenerateRandomKey(64)
	}
	blockKey := securecookie.GenerateRandomKey(32)

	store := sessions.NewCookieStore(hashKey, blockKey)
	return &SessionManager{
		store:      store,
		cookieName: "basic_auth_proxy_auth",
		cookiePath: "/",
		maxAge:     86400,
		secure:     false,
		httpOnly:   true,
		sameSite:   http.SameSiteLaxMode,
	}
}

// ConfigureCookie sets the cookie options for the session store
func (m *SessionManager) ConfigureCookie(name, path, domain string, maxAge int, secure, httpOnly bool, sameSite string) {
	m.cookieName = name
	m.cookiePath = path
	if domain != "localhost" || domain != "127.0.0.1" {
		m.cookieDomain = domain
	} else {
		m.cookieDomain = ""
	}
	m.maxAge = maxAge
	m.secure = secure
	m.httpOnly = httpOnly

	// Parse SameSite value
	switch sameSite {
	case "strict":
		m.sameSite = http.SameSiteStrictMode
	case "lax":
		m.sameSite = http.SameSiteLaxMode
	case "none":
		m.sameSite = http.SameSiteNoneMode
	default:
		m.sameSite = http.SameSiteLaxMode
	}

	// Configure the cookie store
	m.store.Options = &sessions.Options{
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		MaxAge:   m.maxAge,
		Secure:   m.secure,
		HttpOnly: m.httpOnly,
		SameSite: m.sameSite,
	}
}

func (m *SessionManager) Get(r *http.Request, name string) (*sessions.Session, error) {
	return m.store.Get(r, name)
}

func (m *SessionManager) GenerateBasicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func (m *SessionManager) CreateUserSession(w http.ResponseWriter, r *http.Request, sessionName, username, password string) error {
	// Get session
	session, err := m.Get(r, sessionName)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Set session values
	session.Values["authenticated"] = true
	session.Values["auth_user"] = username
	session.Values["auth_pass"] = password
	session.Values["logged_in"] = time.Now().Format(time.RFC3339)

	// Save session
	return session.Save(r, w)
}

func (m *SessionManager) GetUserInfo(r *http.Request, sessionName string) (*UserInfo, error) {
	session, err := m.Get(r, sessionName)
	if err != nil {
		return nil, err
	}

	// Check if user is authenticated
	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		return nil, fmt.Errorf("user not authenticated")
	}

	// Get username
	username, ok := session.Values["auth_user"].(string)
	if !ok {
		return nil, fmt.Errorf("username not found in session")
	}

	// Get password
	password, ok := session.Values["auth_pass"].(string)
	if !ok {
		return nil, fmt.Errorf("password not found in session")
	}

	// Get login time
	loginTimeStr, ok := session.Values["logged_in"].(string)
	if !ok {
		return nil, fmt.Errorf("login time not found in session")
	}

	loginTime, err := time.Parse(time.RFC3339, loginTimeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse login time: %w", err)
	}

	return &UserInfo{
		Username: username,
		Password: password,
		LoggedIn: loginTime,
	}, nil
}

func (m *SessionManager) Destroy(w http.ResponseWriter, r *http.Request, name string) error {
	session, err := m.Get(r, name)
	if err != nil {
		return err
	}

	// Mark session for deletion by setting MaxAge to -1
	session.Options.MaxAge = -1
	return session.Save(r, w)
}

// GetUserInfoJSON returns user info as JSON
func (m *SessionManager) GetUserInfoJSON(r *http.Request, sessionName string) ([]byte, error) {
	userInfo, err := m.GetUserInfo(r, sessionName)
	if err != nil {
		return nil, err
	}

	userInfo.Password = "" // Do not expose password in JSON response

	return json.Marshal(userInfo)
}
