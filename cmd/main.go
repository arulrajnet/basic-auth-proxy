package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	log "github.com/arulrajnet/basic-auth-proxy/pkg/logger"
	"github.com/arulrajnet/basic-auth-proxy/pkg/proxy"
	"github.com/arulrajnet/basic-auth-proxy/pkg/session"
	"github.com/arulrajnet/basic-auth-proxy/pkg/version"
	"github.com/gorilla/mux"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var logger = log.GetLogger()

func main() {
	// Define command line flags
	configFile := pflag.StringP("config", "c", "", "path to the configuration file")
	showVersion := pflag.BoolP("version", "v", false, "print version string")
	logLevel := pflag.StringP("log-level", "l", "info", "set the log level (trace, debug, info, warn, error, fatal, panic)")
	address := pflag.StringP("address", "a", "", "address to listen on")
	port := pflag.IntP("port", "p", 0, "port to listen on")
	proxyPrefix := pflag.StringP("proxy-prefix", "P", "", "prefix path for the proxy")
	upstreamURL := pflag.StringP("upstream", "u", "", "upstream server URL")
	cookieName := pflag.StringP("cookie-name", "s", "", "cookie name")
	cookieSecret := pflag.StringP("cookie-secret", "S", "", "cookie secret key")
	loginLogo := pflag.StringP("logo", "L", "", "Path or URL for the login page logo")
	templateDir := pflag.StringP("template-dir", "T", "", "path to custom login template")
	footerText := pflag.StringP("footer-text", "f", "", "footer text for the login page")
	help := pflag.BoolP("help", "h", false, "show this help message")

	// Parse command line flags
	pflag.Parse()

	// Show help message if requested
	if *help {
		fmt.Fprintf(os.Stderr, "Basic Auth Proxy version %s\n\n", version.VERSION)
		fmt.Fprintf(os.Stderr, "Usage: basic-auth-proxy [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		pflag.PrintDefaults()
		os.Exit(0)
	}

	// Show version if requested
	if *showVersion {
		fmt.Printf("basic-auth-proxy %s (built with %s)\n", version.VERSION, runtime.Version())
		os.Exit(0)
	}

	// Load configuration
	cfg, err := proxy.LoadConfig(*configFile)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to load configuration")
		os.Exit(1)
	}

	// Set log level
	if *logLevel != "info" {
		cfg.LogLevel = *logLevel
		log.SetLogLevel(cfg.LogLevel)
	}

	// Override config with command line flags
	viper.BindPFlag("proxy.address", pflag.Lookup("address"))
	viper.BindPFlag("proxy.port", pflag.Lookup("port"))
	viper.BindPFlag("proxy.prefix", pflag.Lookup("proxy-prefix"))
	viper.BindPFlag("log_level", pflag.Lookup("log-level"))
	viper.BindPFlag("upstreams.0.url", pflag.Lookup("upstream"))
	viper.BindPFlag("upstreams.0.timeout", pflag.Lookup("upstream-timeout"))
	viper.BindPFlag("cookie.name", pflag.Lookup("cookie-name"))
	viper.BindPFlag("cookie.secret_key", pflag.Lookup("cookie-secret"))
	viper.BindPFlag("custom_page.logo", pflag.Lookup("logo"))
	viper.BindPFlag("custom_page.template_dir", pflag.Lookup("template-dir"))
	viper.BindPFlag("custom_page.footer_text", pflag.Lookup("footer-text"))

	// Apply overrides from flags
	if *address != "" {
		cfg.Proxy.Address = *address
	}
	if *port != 0 {
		cfg.Proxy.Port = *port
	}
	if *proxyPrefix != "" {
		cfg.Proxy.ProxyPrefix = *proxyPrefix
	}
	if *upstreamURL != "" && len(cfg.Upstreams) > 0 {
		parsedURL, err := url.Parse(*upstreamURL)
		if err != nil {
			logger.Fatal().Err(err).Str("url", *upstreamURL).Msg("Failed to parse upstream URL")
			os.Exit(1)
		}
		cfg.Upstreams[0].URL = parsedURL
	}
	if *cookieName != "" {
		cfg.Cookie.Name = *cookieName
	}
	if *cookieSecret != "" {
		cfg.Cookie.SecretKey = *cookieSecret
	}
	if *loginLogo != "" {
		cfg.CustomPage.Logo = *loginLogo
	}
	if *templateDir != "" {
		cfg.CustomPage.TemplateDir = *templateDir
	}
	if *footerText != "" {
		cfg.CustomPage.FooterText = *footerText
	}

	// Create session manager
	sessionManager := session.NewSessionManager(cfg.Cookie.SecretKey)

	// Create proxy handler for auth routes (this is the same proxy instance used by middleware)
	proxyHandler := proxy.NewProxy(cfg, sessionManager)

	// Setup router
	r := mux.NewRouter()
	r.Use(proxy.RequestLogger(logger))

	// Add auth routes
	authPrefix := cfg.Proxy.ProxyPrefix
	if authPrefix == "" {
		authPrefix = "/auth"
	}
	authPrefix = strings.TrimSuffix(authPrefix, "/")

	// Auth routes (these bypass session middleware check)
	// r.PathPrefix(authPrefix + "/").Handler(proxyHandler)
	r.PathPrefix("/").Handler(proxyHandler)

	// Create server
	addr := fmt.Sprintf("%s:%d", cfg.Proxy.Address, cfg.Proxy.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  time.Duration(cfg.Proxy.Timeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Proxy.Timeout) * time.Second,
	}

	// Start server
	logger.Info().Str("version", version.VERSION).Msg("Starting Basic Auth Proxy")
	logger.Info().Str("address", addr).Msg("Listening on")
	if err := server.ListenAndServe(); err != nil {
		logger.Fatal().Err(err).Msg("Failed to start server")
		os.Exit(1)
	}
}
