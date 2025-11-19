package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
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

type application struct {
	handler http.Handler
	cfg     config.Config
	pool    *pgxpool.Pool
}

var (
	appOnce     sync.Once
	appInstance *application
	appInitErr  error
)

func initApplication(ctx context.Context) (*application, error) {
	appOnce.Do(func() {
		_ = godotenv.Load()

		cfg, err := config.Load()
		if err != nil {
			appInitErr = err
			return
		}

		pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
		if err != nil {
			appInitErr = err
			return
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			appInitErr = err
			return
		}

		mailer, err := emailpkg.NewSender(cfg.Email)
		if err != nil {
			pool.Close()
			appInitErr = err
			return
		}

		jwtManager := jwtutil.NewManager(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTExpiry)
		repo := repository.NewPostgresRepository(pool)
		authService := authsvc.NewService(repo, mailer, jwtManager, cfg.OTPExpiry)
		authHandler := authhandler.New(authService)
		authMiddleware := middleware.NewAuthMiddleware(jwtManager)
		srv := server.New(authHandler, authMiddleware)

		appInstance = &application{
			handler: srv.Engine,
			cfg:     cfg,
			pool:    pool,
		}
	})

	return appInstance, appInitErr
}

// Handler exposes the HTTP handler required by @vercel/go.
func Handler(w http.ResponseWriter, r *http.Request) {
	app, err := initApplication(r.Context())
	if err != nil {
		log.Printf("bootstrap error: %v", err)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	app.handler.ServeHTTP(w, r)
}

func main() {
	baseCtx := context.Background()
	app, err := initApplication(baseCtx)
	if err != nil {
		log.Fatalf("bootstrap error: %v", err)
	}

	httpServer := &http.Server{
		Addr:    ":" + app.cfg.Port,
		Handler: app.handler,
	}

	go func() {
		log.Printf("listening on :%s", app.cfg.Port)
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
	app.pool.Close()
}
