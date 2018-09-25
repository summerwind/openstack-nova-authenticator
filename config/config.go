package config

// Config represents a configuration file.
type Config struct {
	Listen string          `yaml:"listen"`
	TLS    TLSConfig       `yaml:"tls"`
	Auth   AuthConfig      `yaml:"auth"`
	Roles  map[string]Role `yaml:"roles"`
}

// TLSConfig contains the settings for TLS.
type TLSConfig struct {
	CertFile string `yaml:"certFile"`
	KeyFile  string `yaml:"keyFile"`
}

// AuthConfig contains the settings for Authentication.
type AuthConfig struct {
	Limit          int    `yaml:"limit"`
	Period         string `yaml:"period"`
	SigningKeyFile string `yaml:"signingKeyFile"`
	TokenIssuer    string `yaml:"tokenIssuer"`
	TokenExpiry    string `yaml:"tokenExpiry"`
}

// Role represents a role which is a group of instances.
type Role struct {
	ProjectID string            `yaml:"projectID"`
	UserID    string            `yaml:"userID"`
	Metadata  map[string]string `yaml:"metadata"`
}

// New returns a config with default values.
func New() *Config {
	return &Config{
		Listen: "0.0.0.0:18775",
		TLS:    TLSConfig{},
		Auth: AuthConfig{
			Limit:       3,
			Period:      "5m",
			TokenExpiry: "10m",
		},
	}
}
