package config

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

const DefaultListen = ":8080"

type Config struct {
	DatabaseURL   string
	MasterKey     []byte
	Listen        string
	SignaturesDir string
}

func Load(getenv func(string) string) (Config, error) {
	dbURL := strings.TrimSpace(getenv("ASI_DATABASE_URL"))
	if dbURL == "" {
		return Config{}, errors.New("ASI_DATABASE_URL is not set")
	}
	if !strings.HasPrefix(dbURL, "postgres://") && !strings.HasPrefix(dbURL, "postgresql://") {
		return Config{}, errors.New("ASI_DATABASE_URL is malformed: want postgres://user:password@host:port/db")
	}
	if _, err := pgx.ParseConfig(dbURL); err != nil {
		return Config{}, errors.New("ASI_DATABASE_URL is malformed: want postgres://user:password@host:port/db")
	}

	rawKey := strings.TrimSpace(getenv("ASI_MASTER_KEY"))
	if rawKey == "" {
		return Config{}, errors.New("ASI_MASTER_KEY is not set")
	}
	key, err := base64.StdEncoding.DecodeString(rawKey)
	if err != nil || len(key) != 32 {
		return Config{}, errors.New("ASI_MASTER_KEY is malformed: want base64 of exactly 32 bytes")
	}

	listen := strings.TrimSpace(getenv("ASI_LISTEN"))
	if listen == "" {
		listen = DefaultListen
	}
	return Config{DatabaseURL: dbURL, MasterKey: key, Listen: listen, SignaturesDir: strings.TrimSpace(getenv("ASI_SIGNATURES_DIR"))}, nil
}
