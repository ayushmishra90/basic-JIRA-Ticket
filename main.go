package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ticket-system/internal/api"
	"ticket-system/internal/auth"
	"ticket-system/internal/store"
)

func main() {
	// PORT defaults to 8080 (the local/Docker contract). Hosting platforms
	// that inject their own PORT are supported transparently.
	port := getenv("PORT", "8080")

	// JWT_SECRET must be set in any real deployment. A development fallback
	// keeps local runs frictionless; a warning is logged when it is used.
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "dev-insecure-secret-change-me"
		log.Println("WARNING: JWT_SECRET is not set; using an insecure development secret")
	}

	st := store.New()
	tokens := auth.NewManager(secret, 15*time.Minute, 24*time.Hour)
	server := api.NewServer(st, tokens)

	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start the server in the background.
	go func() {
		log.Printf("ticket-system listening on :%s", port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Wait for an interrupt/termination signal, then shut down gracefully.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Println("stopped")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
