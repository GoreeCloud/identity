package config

import (
	"errors"
	"testing"
)

func TestLoadFromDefaultsToLoopback(t *testing.T) {
	cfg, err := LoadFrom(func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.AdminListenAddress != DefaultAdminListenAddress {
		t.Fatalf("AdminListenAddress = %q, want %q", cfg.AdminListenAddress, DefaultAdminListenAddress)
	}
}

func TestLoadFromAcceptsExplicitLoopback(t *testing.T) {
	for _, value := range []string{"127.0.0.1:8860", "localhost:8860", "[::1]:8860"} {
		t.Run(value, func(t *testing.T) {
			cfg, err := LoadFrom(func(key string) string {
				if key == "GOREECLOUD_IDENTITY_ADMIN_LISTEN" {
					return value
				}
				return ""
			})
			if err != nil {
				t.Fatalf("LoadFrom() error = %v", err)
			}
			if cfg.AdminListenAddress != value {
				t.Fatalf("AdminListenAddress = %q, want %q", cfg.AdminListenAddress, value)
			}
		})
	}
}

func TestLoadFromRejectsNonLoopback(t *testing.T) {
	for _, value := range []string{"0.0.0.0:8860", "10.0.0.10:8860", ":8860", "example.com:8860"} {
		t.Run(value, func(t *testing.T) {
			_, err := LoadFrom(func(key string) string {
				if key == "GOREECLOUD_IDENTITY_ADMIN_LISTEN" {
					return value
				}
				return ""
			})
			if !errors.Is(err, ErrNonLoopbackAdminListen) {
				t.Fatalf("LoadFrom() error = %v, want ErrNonLoopbackAdminListen", err)
			}
		})
	}
}

func TestLoadFromRejectsInvalidPort(t *testing.T) {
	_, err := LoadFrom(func(key string) string {
		if key == "GOREECLOUD_IDENTITY_ADMIN_LISTEN" {
			return "127.0.0.1:70000"
		}
		return ""
	})
	if err == nil {
		t.Fatal("LoadFrom() error = nil, want invalid port error")
	}
}
