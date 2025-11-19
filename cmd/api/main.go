package handler

import (
	"context"
	"log"
	"net/http"
	"sync"

	"auth_demo/pkg/config"
	emailpkg "auth_demo/pkg/email"
	authhandler "auth_demo/pkg/handlers/auth"
	"auth_demo/pkg/jwtutil"
	"auth_demo/pkg/repository"
	"auth_demo/pkg/server"
	"auth_demo/pkg/server/middleware"
	authsvc "auth_demo/pkg/services/auth"

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

// App bundles the HTTP handler and config for long-running servers.
type App struct {
	Handler http.Handler
	Port    string
	closeFn func()
}

// Close releases underlying resources; safe to call multiple times.
func (a *App) Close() {
	if a != nil && a.closeFn != nil {
		a.closeFn()
		a.closeFn = nil
	}
}

// NewApp bootstraps the application for local/server usage.
func NewApp(ctx context.Context) (*App, error) {
	app, err := initApplication(ctx)
	if err != nil {
		return nil, err
	}
	return &App{
		Handler: app.handler,
		Port:    app.cfg.Port,
		closeFn: func() {
			app.pool.Close()
		},
	}, nil
}

// NewHTTPServer builds an *http.Server using the shared handler.
func NewHTTPServer(ctx context.Context) (*http.Server, func(context.Context) error, error) {
	app, err := initApplication(ctx)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{
		Addr:    ":" + app.cfg.Port,
		Handler: app.handler,
	}
	shutdown := func(ctx context.Context) error {
		defer app.pool.Close()
		return srv.Shutdown(ctx)
	}
	return srv, shutdown, nil
}
