package middleware

import (
	"net/http"
	"strings"

	"auth_demo/internal/jwtutil"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ContextUserIDKey stores the UUID of the authenticated user in gin.Context.
const ContextUserIDKey = "authUserID"

// NewAuthMiddleware returns a gin middleware ensuring valid JWT tokens.
func NewAuthMiddleware(jwtManager *jwtutil.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			return
		}
		token := strings.TrimSpace(parts[1])
		claims, err := jwtManager.Verify(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid subject"})
			return
		}
		c.Set(ContextUserIDKey, userID)
		c.Next()
	}
}
