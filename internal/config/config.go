package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"asi/internal/inventory"
)

const DefaultListen = ":8080"

type Config struct {
	DatabaseURL     string
	MasterKey       []byte
	PreviousKeys    [][]byte
	Listen          string
	SignaturesDir   string
	Interest        inventory.InterestWeights
	BodyRetention   int
	VolatileHeaders []string
	Location        *time.Location
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
	var previous [][]byte
	if raw := strings.TrimSpace(getenv("ASI_MASTER_KEY_PREVIOUS")); raw != "" {
		for i, part := range strings.Split(raw, ",") {
			k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(part))
			if err != nil || len(k) != 32 {
				return Config{}, fmt.Errorf("ASI_MASTER_KEY_PREVIOUS is malformed: entry %d is not base64 of exactly 32 bytes; want comma-separated keys", i+1)
			}
			previous = append(previous, k)
		}
	}

	listen := strings.TrimSpace(getenv("ASI_LISTEN"))
	if listen == "" {
		listen = DefaultListen
	}
	interest, err := inventory.ParseInterestWeights(getenv("ASI_INTEREST_WEIGHTS"))
	if err != nil {
		return Config{}, fmt.Errorf("ASI_INTEREST_WEIGHTS is malformed: %w", err)
	}
	retention := inventory.DefaultBodyRetention
	if raw := strings.TrimSpace(getenv("ASI_BODY_RETENTION_RUNS")); raw != "" {
		if retention, err = strconv.Atoi(raw); err != nil || retention < 1 {
			return Config{}, errors.New("ASI_BODY_RETENTION_RUNS is malformed: want a whole number of runs, at least 1")
		}
	}
	var loc *time.Location
	if raw := strings.TrimSpace(getenv("ASI_TIMEZONE")); raw != "" {
		if loc, err = time.LoadLocation(raw); err != nil {
			return Config{}, fmt.Errorf("ASI_TIMEZONE is malformed: want an IANA zone name such as Europe/Warsaw: %w", err)
		}
	}
	return Config{DatabaseURL: dbURL, MasterKey: key, PreviousKeys: previous, Listen: listen, SignaturesDir: strings.TrimSpace(getenv("ASI_SIGNATURES_DIR")),
		Interest: interest, BodyRetention: retention, VolatileHeaders: inventory.ParseHeaderNames(getenv("ASI_VOLATILE_HEADERS")), Location: loc}, nil
}
