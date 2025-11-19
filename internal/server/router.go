package server

import (
	"net/http"

	authhandler "auth_demo/internal/handlers/auth"

	"github.com/gin-gonic/gin"
)

// Server wraps the gin engine and attached routes.
type Server struct {
	Engine *gin.Engine
}

// New builds the HTTP server with all routes wired.
func New(authHandler *authhandler.Handler, authMiddleware gin.HandlerFunc) *Server {
	router := gin.Default()
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := router.Group("/api/v1")
	authGroup := api.Group("/auth")
	authHandler.Register(authGroup, authMiddleware)

	return &Server{Engine: router}
}
