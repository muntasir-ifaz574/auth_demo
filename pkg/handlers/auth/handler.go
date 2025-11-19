package auth

import (
	"net/http"

	"auth_demo/pkg/server/middleware"
	authsvc "auth_demo/pkg/services/auth"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Handler wires HTTP requests to the auth service.
type Handler struct {
	service *authsvc.Service
}

// New creates a new auth HTTP handler.
func New(service *authsvc.Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Register(router *gin.RouterGroup, authRequired gin.HandlerFunc) {
	router.POST("/signup", h.signup)
	router.POST("/signup/verify", h.verifySignup)
	router.POST("/signup/resend", h.resendSignup)

	router.POST("/signin", h.signin)
	router.POST("/signin/verify", h.verifySignin)
	router.POST("/signin/resend", h.resendSignin)

	router.POST("/password/forgot", h.forgotPassword)
	router.POST("/password/forgot/verify", h.verifyForgotPassword)

	protected := router.Group("")
	protected.Use(authRequired)
	protected.PATCH("/password", h.updatePassword)
}

type signupRequest struct {
	Email       string `json:"email"`
	FullName    string `json:"fullName"`
	PhoneNumber string `json:"phoneNumber"`
	Password    string `json:"password"`
}

type verifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"otp"`
}

type signinRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type forgotVerifyRequest struct {
	Email       string `json:"email"`
	Code        string `json:"otp"`
	NewPassword string `json:"newPassword"`
}

type updatePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (h *Handler) signup(c *gin.Context) {
	var req signupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	err := h.service.StartSignup(c.Request.Context(), authsvc.SignupInput{
		Email:       req.Email,
		FullName:    req.FullName,
		PhoneNumber: req.PhoneNumber,
		Password:    req.Password,
	})
	if err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "OTP sent to email"})
}

func (h *Handler) verifySignup(c *gin.Context) {
	var req verifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	result, err := h.service.CompleteSignup(c.Request.Context(), authsvc.VerifyInput{
		Email: req.Email,
		Code:  req.Code,
	})
	if err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"token":     result.Token,
		"expiresAt": result.ExpiresAt,
		"user": gin.H{
			"id":          result.User.ID,
			"email":       result.User.Email,
			"fullName":    result.User.FullName,
			"phoneNumber": result.User.PhoneNumber,
		},
	})
}

func (h *Handler) resendSignup(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if err := h.service.ResendSignupOTP(c.Request.Context(), req.Email); err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "OTP resent"})
}

func (h *Handler) signin(c *gin.Context) {
	var req signinRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if err := h.service.StartSignin(c.Request.Context(), authsvc.SigninInput(req)); err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "OTP sent to email"})
}

func (h *Handler) verifySignin(c *gin.Context) {
	var req verifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	result, err := h.service.VerifySignin(c.Request.Context(), authsvc.VerifyInput(req))
	if err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
    c.JSON(http.StatusOK, gin.H{
        "token":     result.Token,
        "expiresAt": result.ExpiresAt,
        "user": gin.H{
            "id":          result.User.ID,
            "email":       result.User.Email,
            "fullName":    result.User.FullName,
            "phoneNumber": result.User.PhoneNumber,
        },
    })
}

func (h *Handler) resendSignin(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if err := h.service.ResendSigninOTP(c.Request.Context(), req.Email); err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "OTP resent"})
}

func (h *Handler) forgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if err := h.service.StartForgotPassword(c.Request.Context(), req.Email); err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "OTP sent to email"})
}

func (h *Handler) verifyForgotPassword(c *gin.Context) {
	var req forgotVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if err := h.service.CompleteForgotPassword(c.Request.Context(), authsvc.ForgotPasswordVerifyInput(req)); err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password updated"})
}

func (h *Handler) updatePassword(c *gin.Context) {
	var req updatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	userIDVal, exists := c.Get(middleware.ContextUserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing auth context"})
		return
	}
	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid auth context"})
		return
	}
	if err := h.service.UpdatePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword); err != nil {
		c.JSON(statusFromError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password updated"})
}

func statusFromError(err error) int {
	switch err {
	case nil:
		return http.StatusOK
	case authsvc.ErrUserExists:
		return http.StatusConflict
	case authsvc.ErrInvalidCredentials:
		return http.StatusUnauthorized
	case authsvc.ErrOTPNotFound:
		return http.StatusNotFound
	case authsvc.ErrOTPExpired, authsvc.ErrOTPCodeMismatch:
		return http.StatusBadRequest
	case authsvc.ErrUserNotFound:
		return http.StatusNotFound
	case authsvc.ErrSamePassword:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
