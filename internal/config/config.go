package config

import "github.com/kelseyhightower/envconfig"

type Config struct {
	CSApi CSApiConfig `envconfig:"CS"`
	ERApi ERApiConfig `envconfig:"ER"`
}

type CSApiConfig struct {
	Key string `envconfig:"TOKEN"`
	Url string `envconfig:"URL"`
}

type ERApiConfig struct {
	User  string `envconfig:"USER"`
	Pass  string `envconfig:"PASS"`
	Url   string `envconfig:"URL"`
	Group string `envconfig:"GROUP"`
}

func GetConfig() (*Config, error) {
	cfg := Config{}
	err := envconfig.Process("", &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
