package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/rselbach/rgrok/internal/atomicfile"
)

type FileConfig struct {
	Token     string    `json:"token"`
	Login     string    `json:"login"`
	UpdatedAt time.Time `json:"updated_at"`
}

func ConfigPath() (string, error) {
	if path := os.Getenv("RGROK_CONFIG"); path != "" {
		return path, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rgrok", "config.json"), nil
}

func LoadFileConfig() (FileConfig, error) {
	path, err := ConfigPath()
	if err != nil {
		return FileConfig{}, err
	}

	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return FileConfig{}, nil
	}
	if err != nil {
		return FileConfig{}, err
	}
	defer file.Close()

	var cfg FileConfig
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return FileConfig{}, err
	}
	return cfg, nil
}

func SaveFileConfig(cfg FileConfig) error {
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	cfg.UpdatedAt = time.Now().UTC()
	return atomicfile.WriteJSON(path, cfg)
}
