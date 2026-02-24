package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	addr := os.Getenv("BRIDGE_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	store := NewRegistrationStore()

	// PushSender would be a real FCM/APNs client in production.
	// For now, we use a no-op sender that can be replaced via DI.
	var sender PushSender = &LogSender{}

	subscriber := NewNostrSubscriber(nil, store, sender)
	dummy := NewDummyScheduler(store, sender)
	api := NewAPI(store, subscriber)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start background services.
	go subscriber.Start(ctx)
	go dummy.Start(ctx)

	srv := &http.Server{
		Addr:         addr,
		Handler:      api.Router(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down...")
		cancel()
		srv.Shutdown(context.Background())
	}()

	log.Printf("push bridge listening on %s", addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

// LogSender is a no-op push sender that logs instead of sending.
type LogSender struct{}

func (s *LogSender) SendWakeUp(reg Registration) error {
	log.Printf("would send wake-up to %s (platform=%s)", reg.FCMToken[:8]+"...", reg.Platform)
	return nil
}
