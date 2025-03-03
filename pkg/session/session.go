package session

import (
	"encoding/base64"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type SessionManager struct {
	store *sessions.CookieStore
}

func NewSessionManager(secretKey string) *SessionManager {
	// Create a new secure cookie encoder
	hashKey := securecookie.GenerateRandomKey(64)
	blockKey := securecookie.GenerateRandomKey(32)

	store := sessions.NewCookieStore(hashKey, blockKey)
	return &SessionManager{store: store}
}

func (m *SessionManager) Get(r *http.Request, name string) (*sessions.Session, error) {
	return m.store.Get(r, name)
}

func (s *sessions.Session) GenerateBasicAuth(username, password string) string {
	auth := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func (m *SessionManager) Destroy(w http.ResponseWriter, r *http.Request, name string) error {
	session, err := m.Get(r, name)
	if err != nil {
		return err
	}

	session.Options.MaxAge = -1
	return session.Save(r, w)
}
