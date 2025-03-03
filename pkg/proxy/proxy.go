package proxy

import (
	"html/template"
	"net/http"
	"net/http/httputil"
	"net/url"

	log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
	"github.com/arulrajnet/basic-auth-proxy/pkg/session"
)

var logger = log.GetLogger()

type Proxy struct {
	config         *Config
	sessionManager *session.SessionManager
}

func NewProxy(config *Config, sessionManager *session.SessionManager) *Proxy {
	return &Proxy{
		config:         config,
		sessionManager: sessionManager,
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session, _ := p.sessionManager.Get(r, p.config.Session.Name)

	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	upstreamHost := p.config.Upstreams[0].Host // Assuming first upstream for simplicity
	upstreamURL, err := url.Parse(upstreamHost)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to parse upstream URL")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(upstreamURL)

	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = upstreamURL.Scheme
		req.URL.Host = upstreamURL.Host
		req.Host = upstreamURL.Host

		// Set the Authorization header from the session
		if authUser, ok := session.Values["auth_user"].(string); ok {
			if authPass, ok := session.Values["auth_pass"].(string); ok {
				auth := session.GenerateBasicAuth(authUser, authPass)
				req.Header.Set("Authorization", auth)
			}
		}
		// Remove existing X-Forwarded-For header to prevent spoofing
		req.Header.Del("X-Forwarded-For")
	}

	proxy.ServeHTTP(w, r)
}

func LoginHandler(config *Config, sessionManager *session.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			logger.Error().Err(err).Msg("Failed to parse form")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		// Validate credentials against upstream
		upstream := config.Upstreams[0] // Assuming first upstream for simplicity
		if !validateCredentials(upstream, username, password) {
			logger.Warn().Msg("Invalid credentials")
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Create session
		session, err := sessionManager.Get(r, config.Session.Name)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get session")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		session.Values["authenticated"] = true
		session.Values["auth_user"] = username
		session.Values["auth_pass"] = password

		err = session.Save(r, w)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to save session")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func validateCredentials(upstream Upstream, username, password string) bool {
	// Create a new request to the upstream with Basic Auth
	targetURL, err := url.Parse(upstream.Host)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to parse upstream URL")
		return false
	}

	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create request")
		return false
	}

	req.SetBasicAuth(username, password)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to send request to upstream")
		return false
	}
	defer resp.Body.Close()

	// Check the response status code
	return resp.StatusCode == http.StatusOK
}

type LoginPageData struct {
	Title string
	Logo string
	CustomCSS string
}

func LoginPageHandler(config LoginPage, sessionManager *session.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.New("login").Parse(loginTemplate)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to parse login template")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := LoginPageData{
			Title: config.Title,
			Logo: config.Logo,
			CustomCSS: config.CustomCSS,
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to execute login template")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}

const loginTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
	<style>
		body {
			font-family: sans-serif;
			background-color: #f0f0f0;
			display: flex;
			justify-content: center;
			align-items: center;
			height: 100vh;
			margin: 0;
		}
		.login-container {
			background-color: #fff;
			padding: 20px;
			border-radius: 8px;
			box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
			width: 300px;
			text-align: center;
		}
		input[type="text"],
		input[type="password"] {
			width: 100%;
			padding: 10px;
			margin: 10px 0;
			border: 1px solid #ddd;
			border-radius: 4px;
			box-sizing: border-box;
		}
		button {
			background-color: #5cb85c;
			color: white;
			padding: 10px 15px;
			border: none;
			border-radius: 4px;
			cursor: pointer;
		}
		button:hover {
			background-color: #4cae4c;
		}
		.logo {
			max-width: 150px;
			margin-bottom: 20px;
		}
		{{.CustomCSS}}
	</style>
</head>
<body>
    <div class="login-container">
        {{if .Logo}}<img src="{{.Logo}}" alt="Logo" class="logo">{{end}}
        <h2>{{.Title}}</h2>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
`
