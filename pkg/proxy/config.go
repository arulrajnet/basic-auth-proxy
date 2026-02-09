package proxy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Config defines the structure of the configuration file.
type Config struct {
	Proxy      ProxyConfig  `yaml:"proxy" mapstructure:"proxy"`
	Upstreams  []Upstream   `yaml:"upstreams" mapstructure:"upstreams"`
	CustomPage CustomPage   `yaml:"custom_page" mapstructure:"custom_page"`
	LogLevel   string       `yaml:"log_level" mapstructure:"log_level"`
	Version    string       `yaml:"version" mapstructure:"version"`
	Cookie     CookieConfig `yaml:"cookie" mapstructure:"cookie"`
}

type ProxyConfig struct {
	Address     string `yaml:"address" mapstructure:"address"`
	Port        int    `yaml:"port" mapstructure:"port"`
	Timeout     int    `yaml:"timeout" mapstructure:"timeout"` // Timeout in seconds
	ProxyPrefix string `yaml:"prefix" mapstructure:"prefix"`
}

// Upstream defines the structure for each upstream service.
type Upstream struct {
	URL     *url.URL `yaml:"-" mapstructure:"-"`                        // Parsed URL (not directly unmarshaled)
	URLStr  string   `yaml:"url" mapstructure:"url"`                    // Raw URL string for unmarshaling
	Timeout int      `yaml:"timeout" mapstructure:"timeout"`            // Timeout in seconds
}

type CustomPage struct {
	Logo        string `yaml:"logo" mapstructure:"logo"`
	TemplateDir string `yaml:"template_dir" mapstructure:"template_dir"`
	FooterText  string `yaml:"footer_text" mapstructure:"footer_text"`
}

type CookieConfig struct {
	Name      string `yaml:"name" mapstructure:"name"`
	SecretKey string `yaml:"secret_key" mapstructure:"secret_key"`
	BlockKey  string `yaml:"block_key" mapstructure:"block_key"`
	Domain    string `yaml:"domain" mapstructure:"domain"`
	Path      string `yaml:"path" mapstructure:"path"`
	Secure    bool   `yaml:"secure" mapstructure:"secure"`
	HttpOnly  bool   `yaml:"http_only" mapstructure:"http_only"`
	MaxAge    int    `yaml:"max_age" mapstructure:"max_age"`
	SameSite  string `yaml:"same_site" mapstructure:"same_site"`
}

// DefaultConfig returns default configuration values
func DefaultConfig() *Config {
	proxyPrefix := "/auth" // Default proxy prefix
	return &Config{
		Proxy: ProxyConfig{
			Address:     "0.0.0.0",
			Port:        8080,
			Timeout:     30,
			ProxyPrefix: proxyPrefix,
		},
		Upstreams: []Upstream{
			{
				Timeout: 30,
			},
		},
		CustomPage: CustomPage{
			Logo:        "/static/img/logo.svg",
			TemplateDir: "",
			FooterText:  "",
		},
		LogLevel: "info",
		Cookie: CookieConfig{
			Name:     "basic_auth_proxy_session",
			Domain:   "",
			Path:     "/",
			Secure:   false,
			HttpOnly: true,
			MaxAge:   86400,
			SameSite: "lax",
		},
	}
}

// LoadConfig loads the configuration using viper
func LoadConfig(configFile string) (*Config, error) {
	// The order of precedence for configuration is:
	// 1. Command line flags (handled in main.go)
	// 2. Environment variables (handled by viper with BAP_ prefix)
	// 3. Configuration file (if provided)
	// 4. Default values (set in DefaultConfig)

	// Set default configuration
	config := DefaultConfig()

	// Initialize viper
	v := viper.New()

	// Set config file path if provided
	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		// Look for config in default locations
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.basic-auth-proxy")
		v.AddConfigPath("/etc/basic-auth-proxy")
	}

	// Read config file FIRST  (lowest priority after defaults)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error occurred
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// No config file found, will use defaults and env vars
		logger.Info().Msg("No config file found, using defaults and env vars")
	} else {
		logger.Info().Str("file", v.ConfigFileUsed()).Msg("Loaded config file")
	}

	// Set environment variable prefix and bind (SECOND - higher priority than config file)
	v.SetEnvPrefix("BAP")
	v.AutomaticEnv()
	bindEnvs(v, config)

	logger.Debug().Bool("parsed", pflag.CommandLine.Parsed()).Msg("pflag command line parsed")

	// Bind pflags LAST (highest priority - overrides everything)
	if pflag.CommandLine.Parsed() {
			logger.Debug().Msg("Binding command line flags")
			v.BindPFlag("proxy.address", pflag.Lookup("address"))
			v.BindPFlag("proxy.port", pflag.Lookup("port"))
			v.BindPFlag("proxy.prefix", pflag.Lookup("proxy-prefix"))
			v.BindPFlag("log_level", pflag.Lookup("log-level"))
			v.BindPFlag("upstreams.0.url", pflag.Lookup("upstream"))
			v.BindPFlag("upstreams.0.timeout", pflag.Lookup("upstream-timeout"))
			v.BindPFlag("cookie.name", pflag.Lookup("cookie-name"))
			v.BindPFlag("cookie.secret_key", pflag.Lookup("cookie-secret"))
			v.BindPFlag("cookie.block_key", pflag.Lookup("cookie-block"))
			v.BindPFlag("custom_page.logo", pflag.Lookup("logo"))
			v.BindPFlag("custom_page.template_dir", pflag.Lookup("template-dir"))
			v.BindPFlag("custom_page.footer_text", pflag.Lookup("footer-text"))
	}

	// Unmarshal config into struct
	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Update logo if prefix changed and logo is still default
	if config.CustomPage.Logo == "" || config.CustomPage.Logo == "/static/img/logo.svg" {
		config.CustomPage.Logo = strings.TrimSuffix(config.Proxy.ProxyPrefix, "/") + "/static/img/logo.svg"
	}

	logger.Info().Interface("config", config).Msg("loaded configuration")

	// Post-process configuration to handle URL parsing from environment variables
	if err := processURLs(v, config); err != nil {
		return nil, fmt.Errorf("failed to process URLs: %w", err)
	}

	return config, nil
}

// bindEnvs recursively binds all nested config struct fields to environment variables
func bindEnvs(v *viper.Viper, config *Config) {
	v.BindEnv("proxy.address", "BAP_PROXY_ADDRESS")
	v.BindEnv("proxy.port", "BAP_PROXY_PORT")
	v.BindEnv("proxy.timeout", "BAP_PROXY_TIMEOUT")
	v.BindEnv("proxy.prefix", "BAP_PROXY_PREFIX")

	v.BindEnv("custom_page.logo", "BAP_CUSTOM_PAGE_LOGO")
	v.BindEnv("custom_page.template_dir", "BAP_CUSTOM_PAGE_TEMPLATE_DIR")
	v.BindEnv("custom_page.footer_text", "BAP_CUSTOM_PAGE_FOOTER_TEXT")

	v.BindEnv("log_level", "BAP_LOG_LEVEL")

	v.BindEnv("cookie.name", "BAP_COOKIE_NAME")
	v.BindEnv("cookie.secret_key", "BAP_COOKIE_SECRET_KEY")
	v.BindEnv("cookie.block_key", "BAP_COOKIE_BLOCK_KEY")
	v.BindEnv("cookie.domain", "BAP_COOKIE_DOMAIN")
	v.BindEnv("cookie.path", "BAP_COOKIE_PATH")
	v.BindEnv("cookie.secure", "BAP_COOKIE_SECURE")
	v.BindEnv("cookie.http_only", "BAP_COOKIE_HTTP_ONLY")
	v.BindEnv("cookie.max_age", "BAP_COOKIE_MAX_AGE")
	v.BindEnv("cookie.same_site", "BAP_COOKIE_SAME_SITE")

	// Bind upstreams as strings to be processed later
	v.BindEnv("upstreams.0.url", "BAP_UPSTREAM_URL")
	v.BindEnv("upstreams.0.timeout", "BAP_UPSTREAM_TIMEOUT")
}

// processURLs handles parsing of URL strings from config and environment variables
func processURLs(v *viper.Viper, config *Config) error {
	// Process all upstream URLs
	for i := range config.Upstreams {
		var urlStr string

		// First check if there's a URL string from config file
		if config.Upstreams[i].URLStr != "" {
			urlStr = config.Upstreams[i].URLStr
		}

		// Override with environment variable if present (only for first upstream for now)
		if i == 0 {
			if envURL := v.GetString("upstreams.0.url"); envURL != "" {
				urlStr = envURL
			}
		}

		// Parse the URL if we have one
		if urlStr != "" {
			parsedURL, err := url.Parse(urlStr)
			if err != nil {
				return fmt.Errorf("failed to parse upstream URL '%s': %w", urlStr, err)
			}
			config.Upstreams[i].URL = parsedURL
		}
	}

	// Handle case where environment variable is set but no upstreams in config
	if len(config.Upstreams) == 0 {
		if upstreamURLStr := v.GetString("upstreams.0.url"); upstreamURLStr != "" {
			parsedURL, err := url.Parse(upstreamURLStr)
			if err != nil {
				return fmt.Errorf("failed to parse upstream URL '%s': %w", upstreamURLStr, err)
			}

			// Create new upstream from environment variable
			upstream := Upstream{
				URL:     parsedURL,
				URLStr:  upstreamURLStr,
				Timeout: v.GetInt("upstreams.0.timeout"),
			}

			// Set default timeout if not specified
			if upstream.Timeout == 0 {
				upstream.Timeout = 30
			}

			config.Upstreams = append(config.Upstreams, upstream)
		}
	}

	return nil
}
