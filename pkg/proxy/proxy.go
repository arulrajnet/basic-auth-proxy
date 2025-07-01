package proxy

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
	"github.com/arulrajnet/basic-auth-proxy/pkg/session"
	"github.com/arulrajnet/basic-auth-proxy/pkg/templates"
	"github.com/arulrajnet/basic-auth-proxy/pkg/version"
)

var logger = log.GetLogger()

type Proxy struct {
	config         *Config
	sessionManager *session.SessionManager
	reverseProxy   *httputil.ReverseProxy
	proxyPrefix    string
	staticFiles    embed.FS
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
		proxyPrefix:    strings.TrimSuffix(config.Proxy.ProxyPrefix, "/"),
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

// SetStaticFiles configures the embedded static files for the proxy
func (p *Proxy) SetStaticFiles(staticFiles embed.FS) {
	p.staticFiles = staticFiles
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
		} else if strings.HasPrefix(path, p.proxyPrefix+"/static/") {
			p.handleStaticFiles(w, r)
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
		} else if strings.HasPrefix(path, "/static/") {
			p.handleStaticFiles(w, r)
			return
		}
	}

	// Build login path with redirect parameter
	loginPath := "/login"
	if p.proxyPrefix != "" && p.proxyPrefix != "/" {
		loginPath = p.proxyPrefix + "/login"
	}

	// Add current path as redirect parameter
	redirectPath := r.URL.RequestURI()
	if redirectPath != loginPath && !strings.Contains(redirectPath, "/login") {
		q := url.Values{}
		q.Add("redirect", redirectPath)
		loginPath = fmt.Sprintf("%s?%s", loginPath, q.Encode())
	}

	// For all other requests, check authentication and proxy to upstream
	session, err := p.sessionManager.Get(r, p.config.Cookie.Name)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get session")
		http.Redirect(w, r, loginPath, http.StatusFound)
		return
	}

	// Check if session exists
	if session == nil {
		http.Redirect(w, r, loginPath, http.StatusFound)
		return
	}

	// Check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		logger.Info().Str("path", r.URL.Path).Msg("Unauthenticated request")
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
		// Check if user is already authenticated
		if userInfo, err := p.sessionManager.GetUserInfo(r, p.config.Cookie.Name); err == nil && userInfo != nil {
			// User is already logged in, redirect to root
			redirectPath := "/"
			http.Redirect(w, r, redirectPath, http.StatusFound)
			return
		}

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
	// Redirect to login page
	loginPath := "/login"
	if p.proxyPrefix != "" && p.proxyPrefix != "/" {
		loginPath = p.proxyPrefix + "/login"
	}
	// Destroy the session
	err := p.sessionManager.Destroy(w, r, p.config.Cookie.Name)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to destroy session")
		// Try to clear the cookie even if session destruction failed
		cookie := &http.Cookie{
			Name:     p.config.Cookie.Name,
			Value:    "",
			Path:     p.config.Cookie.Path,
			Domain:   p.config.Cookie.Domain,
			MaxAge:   -1,
			Expires:  time.Now().Add(-1 * time.Hour),
			Secure:   p.config.Cookie.Secure,
			HttpOnly: p.config.Cookie.HttpOnly,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, loginPath, http.StatusFound)
		return
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
		ProxyPrefix string
		Logo       string
		Year       int
		Version    string
		FooterText string
		Error      string
	}{
		ProxyPrefix: p.proxyPrefix,
		Logo:       p.config.CustomPage.Logo,
		Year:       time.Now().Year(),
		Version:    version.VERSION,
		FooterText: p.config.CustomPage.FooterText,
		Error:      r.URL.Query().Get("error"),
	}

	// If logo is empty, use placeholder
	if data.Logo == "" {
		data.Logo = "https://via.placeholder.com/120x60?text=Logo"
	}

	// Check if a custom template path is provided
	if p.config.CustomPage.TemplateDir != "" {
		// Load template from file
		tmpl, err = template.ParseFiles(p.config.CustomPage.TemplateDir + "/login.html")
		if err != nil {
			logger.Error().Err(err).Str("path", p.config.CustomPage.TemplateDir).Msg("Failed to parse custom login template")
			// Fall back to default template
			tmpl, err = template.New("login").Parse(templates.LoginTemplate)
			if err != nil {
				logger.Error().Err(err).Msg("Failed to parse default login template")
				http.Error(w, "Template Error", http.StatusInternalServerError)
				return
			}
		}
	} else {
		// Use default template
		tmpl, err = template.New("login").Parse(templates.LoginTemplate)
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

// Handle static file requests
func (p *Proxy) handleStaticFiles(w http.ResponseWriter, r *http.Request) {
	// Extract the file path from the request
	var filePath string
	if p.proxyPrefix != "" && p.proxyPrefix != "/" {
		// Remove proxy prefix and "/static" from the path
		filePath = strings.TrimPrefix(r.URL.Path, p.proxyPrefix+"/static")
	} else {
		// Remove "/static" from the path
		filePath = strings.TrimPrefix(r.URL.Path, "/static")
	}

	// Remove leading slash if present
	filePath = strings.TrimPrefix(filePath, "/")

	// Prevent directory traversal attacks
	if strings.Contains(filePath, "..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Add security headers for static files
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Use embedded static files if available, fallback to filesystem
	if p.staticFiles != (embed.FS{}) {
		// Get the embedded static filesystem rooted at static
		staticFS, err := fs.Sub(p.staticFiles, "static")
		if err != nil {
			logger.Error().Err(err).Msg("Failed to get embedded static filesystem")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Create file server with the embedded filesystem
		fileServer := http.FileServer(http.FS(staticFS))

		// Create a new request with the cleaned path
		r.URL.Path = "/" + filePath

		// Serve the file
		fileServer.ServeHTTP(w, r)
	} else {
		// Fallback to regular filesystem
		fileServer := http.FileServer(http.Dir("static"))

		// Create a new request with the cleaned path
		r.URL.Path = "/" + filePath

		// Serve the file
		fileServer.ServeHTTP(w, r)
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
