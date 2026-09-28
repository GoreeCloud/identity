package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const DefaultAdminListenAddress = "127.0.0.1:8860"

var ErrNonLoopbackAdminListen = errors.New("Identity Development service must listen on loopback only")

type Config struct {
	AdminListenAddress string
}

func Load() (Config, error) {
	return LoadFrom(os.Getenv)
}

func LoadFrom(getenv func(string) string) (Config, error) {
	addr := strings.TrimSpace(getenv("GOREECLOUD_IDENTITY_ADMIN_LISTEN"))
	if addr == "" {
		addr = DefaultAdminListenAddress
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return Config{}, fmt.Errorf("parse GOREECLOUD_IDENTITY_ADMIN_LISTEN: %w", err)
	}
	if host == "" || !isExplicitLoopback(host) {
		return Config{}, fmt.Errorf("%w: %q", ErrNonLoopbackAdminListen, addr)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Config{}, fmt.Errorf("invalid admin listen port %q", port)
	}
	return Config{AdminListenAddress: addr}, nil
}

func isExplicitLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
