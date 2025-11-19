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

	handlerpkg "auth_demo/cmd/api"
)

func main() {
	baseCtx := context.Background()
	app, err := handlerpkg.NewApp(baseCtx)
	if err != nil {
		log.Fatalf("bootstrap error: %v", err)
	}
	defer app.Close()

	httpServer := &http.Server{
		Addr:    ":" + app.Port,
		Handler: app.Handler,
	}

	go func() {
		log.Printf("listening on :%s", app.Port)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("shutting down server ...")

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctxShutdown); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}
