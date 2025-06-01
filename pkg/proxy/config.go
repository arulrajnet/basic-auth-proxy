package proxy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config defines the structure of the configuration file.
type Config struct {
	Proxy    ProxyConfig  `yaml:"proxy"`
	Upstreams []Upstream  `yaml:"upstreams"`
	Session  Session      `yaml:"session"`
	LoginPage LoginPage   `yaml:"login_page"`
}

type ProxyConfig struct {
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
}

// Upstream defines the structure for each upstream service.
type Upstream struct {
	Name     string `yaml:"name"`
	Host     string `yaml:"host"`
	AuthUser string `yaml:"auth_user"`
	AuthPass string `yaml:"auth_pass"`
}

type Session struct {
	Name string `yaml:"name"`
	SecretKey string `yaml:"secret_key"`
	Domain string `yaml:"domain"`
	MaxAge int `yaml:"max_age"`
	Secure bool `yaml:"secure"`
	HttpOnly bool `yaml:"http_only"`
	SameSite string `yaml:"same_site"`
}

type LoginPage struct {
	Title     string `yaml:"title"`
	Logo      string `yaml:"logo"`
	CustomCSS string `yaml:"custom_css"`
}

// LoadConfig loads the configuration from the specified file path.
func LoadConfig(path string) (*Config, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	err = yaml.Unmarshal(f, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return cfg, nil
}
