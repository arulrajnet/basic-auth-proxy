package proxy

import (
	"fmt"
	"html/template"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
	"github.com/arulrajnet/basic-auth-proxy/pkg/session"
	"github.com/arulrajnet/basic-auth-proxy/pkg/version"
)

var logger = log.GetLogger()

type Proxy struct {
	config         *Config
	sessionManager *session.SessionManager
	reverseProxy   *httputil.ReverseProxy
	proxyPrefix    string
}

func NewProxy(config *Config, sessionManager *session.SessionManager) *Proxy {
	// Configure session manager with cookie settings
	sessionManager.ConfigureCookie(
		config.Cookie.Name,
		config.Cookie.Path,
		config.Cookie.Domain,
		config.Cookie.MaxAge,
		config.Cookie.Secure,
		config.Cookie.HttpOnly,
		config.Cookie.SameSite,
	)

	// Create proxy with specified prefix
	p := &Proxy{
		config:         config,
		sessionManager: sessionManager,
		proxyPrefix:    strings.TrimSuffix(config.ProxyPrefix, "/"),
	}

	// Setup reverse proxy to the first upstream
	if len(config.Upstreams) > 0 {
		upstreamURL := config.Upstreams[0].URL
		if upstreamURL == nil {
			logger.Error().Msg("Upstream URL is not configured")
		} else {
			p.reverseProxy = httputil.NewSingleHostReverseProxy(upstreamURL)

			// Set custom director to modify requests
			originalDirector := p.reverseProxy.Director
			p.reverseProxy.Director = func(req *http.Request) {
				originalDirector(req)

				// Get user session
				session, err := sessionManager.Get(req, config.Cookie.Name)
				if err == nil {
					if auth, ok := session.Values["authenticated"].(bool); ok && auth {
						if authUser, ok := session.Values["auth_user"].(string); ok {
							if authPass, ok := session.Values["auth_pass"].(string); ok {
								auth := sessionManager.GenerateBasicAuth(authUser, authPass)
								req.Header.Set("Authorization", auth)
							}
						}
					}
				}

				// Remove sensitive headers
				req.Header.Del("X-Forwarded-For")

				// Set real client IP
				req.Header.Set("X-Real-IP", req.RemoteAddr)

				// Set proxy prefix if needed
				if p.proxyPrefix != "" && p.proxyPrefix != "/" {
					// Remove proxy prefix from URL path
					path := req.URL.Path
					if strings.HasPrefix(path, p.proxyPrefix) {
						newPath := strings.TrimPrefix(path, p.proxyPrefix)
						if newPath == "" {
							newPath = "/"
						}
						req.URL.Path = newPath
						logger.Debug().Str("original_path", path).Str("new_path", newPath).Msg("Rewrote URL path")
					}
				}
			}

			// Set custom timeout
			timeout := time.Duration(config.Proxy.Timeout) * time.Second
			p.reverseProxy.Transport = &http.Transport{
				ResponseHeaderTimeout: timeout,
			}
		}
	}

	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if the request is for an auth endpoint
	path := r.URL.Path
	if p.proxyPrefix != "" && p.proxyPrefix != "/" {
		// If there's a proxy prefix, check if the request is for a prefixed auth endpoint
		if path == p.proxyPrefix+"/sign_in" || path == p.proxyPrefix+"/login" {
			p.handleSignIn(w, r)
			return
		} else if path == p.proxyPrefix+"/sign_out" || path == p.proxyPrefix+"/logout" {
			p.handleSignOut(w, r)
			return
		} else if path == p.proxyPrefix+"/user_info" {
			p.handleUserInfo(w, r)
			return
		}
	} else {
		// No proxy prefix, check regular auth endpoints
		if path == "/sign_in" || path == "/login" {
			p.handleSignIn(w, r)
			return
		} else if path == "/sign_out" || path == "/logout" {
			p.handleSignOut(w, r)
			return
		} else if path == "/user_info" {
			p.handleUserInfo(w, r)
			return
		}
	}

	// For all other requests, check authentication and proxy to upstream
	session, err := p.sessionManager.Get(r, p.config.Cookie.Name)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get session")
		http.Error(w, "Session Error", http.StatusInternalServerError)
		return
	}

	// Check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		// Redirect to login page
		loginPath := "/login"
		if p.proxyPrefix != "" && p.proxyPrefix != "/" {
			loginPath = p.proxyPrefix + "/login"
		}
		http.Redirect(w, r, loginPath, http.StatusFound)
		return
	}

	// User is authenticated, proxy the request
	if p.reverseProxy != nil {
		logger.Debug().Str("path", r.URL.Path).Msg("Proxying request")
		p.reverseProxy.ServeHTTP(w, r)
	} else {
		logger.Error().Msg("Reverse proxy not configured")
		http.Error(w, "Proxy Not Configured", http.StatusInternalServerError)
	}
}

// Handle sign-in requests (both GET for form and POST for credentials)
func (p *Proxy) handleSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Serve the login page
		p.serveLoginPage(w, r)
		return
	} else if r.Method == http.MethodPost {
		// Process login form
		err := r.ParseForm()
		if err != nil {
			logger.Error().Err(err).Msg("Failed to parse login form")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		username := r.Form.Get("username")
		password := r.Form.Get("password")

		if username == "" || password == "" {
			logger.Warn().Msg("Missing username or password")
			p.serveLoginPage(w, r)
			return
		}

		// Validate credentials against upstream
		if len(p.config.Upstreams) == 0 {
			logger.Error().Msg("No upstream configured")
			http.Error(w, "Server Configuration Error", http.StatusInternalServerError)
			return
		}

		upstream := p.config.Upstreams[0] // Using first upstream
		if validated, err := p.validateCredentials(upstream, username, password); err != nil {
			logger.Error().Err(err).Msg("Error validating credentials")
			http.Error(w, "Authentication Error", http.StatusInternalServerError)
			return
		} else if !validated {
			logger.Warn().Str("username", username).Msg("Invalid credentials")
			p.serveLoginPage(w, r)
			return
		}

		// Create user session
		err = p.sessionManager.CreateUserSession(w, r, p.config.Cookie.Name, username, password)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to create user session")
			http.Error(w, "Session Error", http.StatusInternalServerError)
			return
		}

		// Redirect to home or requested path
		redirectPath := "/"
		if p.proxyPrefix != "" && p.proxyPrefix != "/" {
			redirectPath = p.proxyPrefix
		}

		// Check if there's a redirect URL in the query
		if redirectURL := r.URL.Query().Get("redirect"); redirectURL != "" {
			redirectPath = redirectURL
		}

		http.Redirect(w, r, redirectPath, http.StatusFound)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// Handle sign-out requests
func (p *Proxy) handleSignOut(w http.ResponseWriter, r *http.Request) {
	// Destroy the session
	err := p.sessionManager.Destroy(w, r, p.config.Cookie.Name)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to destroy session")
		http.Error(w, "Session Error", http.StatusInternalServerError)
		return
	}

	// Redirect to login page
	loginPath := "/login"
	if p.proxyPrefix != "" && p.proxyPrefix != "/" {
		loginPath = p.proxyPrefix + "/login"
	}
	http.Redirect(w, r, loginPath, http.StatusFound)
}

// Handle user_info requests
func (p *Proxy) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	// Get user info from session
	userInfoJSON, err := p.sessionManager.GetUserInfoJSON(r, p.config.Cookie.Name)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get user info")
		http.Error(w, "Not Authenticated", http.StatusUnauthorized)
		return
	}

	// Return user info as JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(userInfoJSON)
}

// Serve the login page
func (p *Proxy) serveLoginPage(w http.ResponseWriter, r *http.Request) {
	var tmpl *template.Template
	var err error

	// Data for the template
	data := struct {
		Title      string
		Logo       string
		CustomCSS  string
		Year       int
		Version    string
		FooterText string
		Error      string
	}{
		Title:      p.config.LoginPage.Title,
		Logo:       p.config.LoginPage.Logo,
		CustomCSS:  p.config.LoginPage.CustomCSS,
		Year:       time.Now().Year(),
		Version:    version.VERSION,
		FooterText: p.config.FooterText,
		Error:      r.URL.Query().Get("error"),
	}

	// If logo is empty, use placeholder
	if data.Logo == "" {
		data.Logo = "https://via.placeholder.com/120x60?text=Logo"
	}

	// If footer text is empty, use default
	if data.FooterText == "" {
		data.FooterText = fmt.Sprintf("Powered by ProxyAuth v%s © %d", version.VERSION, time.Now().Year())
	}

	// Check if a custom template path is provided
	if p.config.LoginPage.TemplatePath != "" {
		// Load template from file
		tmpl, err = template.ParseFiles(p.config.LoginPage.TemplatePath)
		if err != nil {
			logger.Error().Err(err).Str("path", p.config.LoginPage.TemplatePath).Msg("Failed to parse custom login template")
			// Fall back to default template
			tmpl, err = template.New("login").Parse(loginTemplate)
			if err != nil {
				logger.Error().Err(err).Msg("Failed to parse default login template")
				http.Error(w, "Template Error", http.StatusInternalServerError)
				return
			}
		}
	} else {
		// Use default template
		tmpl, err = template.New("login").Parse(loginTemplate)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to parse default login template")
			http.Error(w, "Template Error", http.StatusInternalServerError)
			return
		}
	}

	// Execute template
	err = tmpl.Execute(w, data)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to execute login template")
		http.Error(w, "Template Error", http.StatusInternalServerError)
		return
	}
}

// Validate user credentials against upstream server
func (p *Proxy) validateCredentials(upstream Upstream, username, password string) (bool, error) {
	// Create a new request to the upstream
	targetURL, err := url.Parse(upstream.URL.String())
	if err != nil {
		return false, fmt.Errorf("failed to parse upstream URL: %w", err)
	}

	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	// Set Basic Auth header
	req.SetBasicAuth(username, password)

	// Set timeout for the request
	timeout := time.Duration(upstream.Timeout)
	if timeout == 0 {
		timeout = time.Duration(p.config.Proxy.Timeout)
	}
	if timeout == 0 {
		timeout = 30 // Default to 30 seconds if not set
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: timeout * time.Second,
	}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send request to upstream: %w", err)
	}
	defer resp.Body.Close()

	// Check response status code
	return resp.StatusCode == http.StatusOK, nil
}

// Login page template
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
            border: none;
            cursor: pointer;
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
        .error-message {
            color: #e74c3c;
            margin-bottom: 1rem;
            font-size: 0.9rem;
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
        {{ if .Error }}
            <div class="error-message">{{ .Error }}</div>
        {{ end }}
        <form action="login" method="post">
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
        <footer>
            {{ .FooterText }}
        </footer>
    </div>
</body>
</html>
`
