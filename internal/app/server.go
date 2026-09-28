package app

import (
	"encoding/json"
	"net/http"
	"time"
)

type statusResponse struct {
	Service string `json:"service"`
	Status  string `json:"status"`
}

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", statusHandler("ok"))
	mux.HandleFunc("/readyz", statusHandler("ready"))
	return securityHeaders(mux)
}

func NewServer(address string) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func statusHandler(status string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(statusResponse{Service: "goreecloud-identity", Status: status})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
