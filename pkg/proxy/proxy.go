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
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body {
            background-color: #f7f7f7;
            font-family: 'Roboto', sans-serif;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 6px 15px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 100%;
            padding: 2rem;
            text-align: center;
        }
        .login-container h1 {
            font-size: 2rem;
            color: #333;
            margin-bottom: 1rem;
        }
        .logo {
            margin: 2rem 0;
        }
        .logo img {
            max-width: 120px;
            margin: 0 auto;
        }
        .field {
            margin-bottom: 1.5rem;
        }
        .input {
            border-radius: 4px;
            border: 1px solid #ccc;
            padding: 0.75rem;
            width: 100%;
            box-sizing: border-box;
        }
        .button.is-primary {
            background-color: #3273dc;
            color: white;
            width: 100%;
            padding: 1rem;
            border-radius: 4px;
            font-size: 1.1rem;
            transition: background-color 0.3s ease;
            margin-top: 1rem;
        }
        .button.is-primary:hover {
            background-color: #276fa3;
        }
        footer {
            text-align: center;
            margin-top: 1rem;
            font-size: 0.9rem;
            color: #555;
        }
        footer a {
            color: #3273dc;
            text-decoration: none;
        }
        {{.CustomCSS}}
    </style>
</head>
<body>
    <div class="login-container">
        {{ if .Title }}
            <h1>{{ .Title }}</h1>
        {{ end }}
        {{ if .Logo }}
            <div class="logo">
                <img src="{{.Logo}}" alt="Logo">
            </div>
        {{ end }}
        <form action="/login" method="post">
            <div class="field">
                <label class="label has-text-weight-bold">Username</label>
                <div class="control">
                    <input class="input" type="text" name="username" placeholder="Username" required>
                </div>
            </div>
            <div class="field">
                <label class="label has-text-weight-bold">Password</label>
                <div class="control">
                    <input class="input" type="password" name="password" placeholder="Password" required>
                </div>
            </div>
            <div class="field">
                <div class="control">
                    <button class="button is-primary" type="submit">Sign In</button>
                </div>
            </div>
        </form>
    </div>
</body>
</html>
`
