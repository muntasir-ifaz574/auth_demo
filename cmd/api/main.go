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

	"auth_demo/internal/config"
	emailpkg "auth_demo/internal/email"
	authhandler "auth_demo/internal/handlers/auth"
	"auth_demo/internal/jwtutil"
	"auth_demo/internal/repository"
	"auth_demo/internal/server"
	"auth_demo/internal/server/middleware"
	authsvc "auth_demo/internal/services/auth"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

func main() {
	ctx := context.Background()
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("db pool error: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("unable to reach database: %v", err)
	}

	mailer, err := emailpkg.NewSender(cfg.Email)
	if err != nil {
		log.Fatalf("email sender error: %v", err)
	}

	jwtManager := jwtutil.NewManager(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTExpiry)
	repo := repository.NewPostgresRepository(pool)
	authService := authsvc.NewService(repo, mailer, jwtManager, cfg.OTPExpiry)
	authHandler := authhandler.New(authService)
	authMiddleware := middleware.NewAuthMiddleware(jwtManager)
	srv := server.New(authHandler, authMiddleware)

	httpServer := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: srv.Engine,
	}

	go func() {
		log.Printf("listening on :%s", cfg.Port)
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
