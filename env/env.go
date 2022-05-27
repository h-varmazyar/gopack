package env

import (
	"errors"
	"github.com/caarlos0/env/v6"
	"github.com/joho/godotenv"
	"os"
)

func Load(path string, configs interface{}) error {
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return errors.New(".env file not available")
			}
			return errors.New("failed to load .env")
		}
	}

	if err := godotenv.Load(path); err != nil {
		return err
	}

	if err := env.Parse(configs); err != nil {
		return err
	}
	return nil
}
