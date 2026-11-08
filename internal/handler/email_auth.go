package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/internal/services"
	"opendomain/pkg/logger"
	"opendomain/pkg/timeutil"
)

const (
	verifyEmailTokenTTL   = 24 * time.Hour
	resetPasswordTokenTTL = time.Hour

	forgotPasswordIPLimit    = 5
	forgotPasswordEmailLimit = 3
	forgotPasswordWindow     = time.Hour

	resendVerificationCooldown    = 60 * time.Second
	resendVerificationHourlyLimit = 5
	resendVerificationWindow      = time.Hour

	passwordMinLength = 6
	// bcrypt only looks at the first 72 bytes and Go's implementation rejects longer input.
	passwordMaxBytes = 72

	emailTokenMaxLength = 128
)

var errInvalidEmailToken = errors.New("invalid or expired email token")

func generateEmailToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashEmailToken(raw), nil
}

func hashEmailToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// issueEmailToken stores a new token and retires any earlier unused token for
// the same user and purpose, so only the most recent link works.
func issueEmailToken(db *gorm.DB, userID uint, purpose, email string, ttl time.Duration, now time.Time) (string, error) {
	raw, hash, err := generateEmailToken()
	if err != nil {
		return "", err
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&models.EmailToken{}).
			Where("user_id = ? AND purpose = ? AND used_at IS NULL", userID, purpose).
			Update("used_at", now).Error; err != nil {
			return err
		}
		return tx.Create(&models.EmailToken{
			UserID:    userID,
			Purpose:   purpose,
			TokenHash: hash,
			Email:     email,
			ExpiresAt: now.Add(ttl),
			CreatedAt: now,
		}).Error
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// consumeEmailToken marks the token used with a single conditional UPDATE so
// two concurrent requests cannot both redeem it.
func consumeEmailToken(tx *gorm.DB, raw, purpose string, now time.Time) (*models.EmailToken, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > emailTokenMaxLength {
		return nil, errInvalidEmailToken
	}
	hash := hashEmailToken(raw)
	res := tx.Model(&models.EmailToken{}).
		Where("token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?", hash, purpose, now).
		Update("used_at", now)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected != 1 {
		return nil, errInvalidEmailToken
	}
	var tok models.EmailToken
	if err := tx.Where("token_hash = ?", hash).First(&tok).Error; err != nil {
		return nil, err
	}
	return &tok, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func frontendLink(base, path, token string) string {
	return strings.TrimRight(base, "/") + path + "?token=" + token
}

func invalidTokenResponse(c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{
		"error": tr(c, "auth.invalid_token", "This link is invalid or has expired. Please request a new one."),
		"code":  "invalid_token",
	})
}

// requireVerifiedEmail writes the 403 response and returns false when the
// user has not verified their email yet.
func requireVerifiedEmail(c *gin.Context, user *models.User) bool {
	if user.EmailVerified {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{
		"error": tr(c, "error.email_not_verified", "Verify your email address before claiming a domain."),
		"code":  "email_not_verified",
	})
	return false
}

// incrRateWindow increments a fixed-window counter, repairing the TTL if a
// previous EXPIRE was lost.
func incrRateWindow(ctx context.Context, rdb *redis.Client, key string, window time.Duration) (int64, error) {
	n, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		rdb.Expire(ctx, key, window)
	} else if ttl, terr := rdb.TTL(ctx, key).Result(); terr == nil && ttl < 0 {
		rdb.Expire(ctx, key, window)
	}
	return n, nil
}

// allowForgotPassword fails open when Redis is unavailable: blocking password
// resets entirely would be worse than briefly losing the limit.
func (h *UserHandler) allowForgotPassword(ctx context.Context, ip, email string) bool {
	if h.rdb == nil {
		return true
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	perIP, err := incrRateWindow(rctx, h.rdb, "forgot_password:rate:ip:"+ip, forgotPasswordWindow)
	if err != nil {
		logger.Warnf("forgot password rate limit: redis unavailable, allowing request: %v", err)
		return true
	}
	perEmail, err := incrRateWindow(rctx, h.rdb, "forgot_password:rate:email:"+hashEmailToken(email), forgotPasswordWindow)
	if err != nil {
		logger.Warnf("forgot password rate limit: redis unavailable, allowing request: %v", err)
		return true
	}
	return perIP <= forgotPasswordIPLimit && perEmail <= forgotPasswordEmailLimit
}

func (h *UserHandler) sendVerificationEmail(user *models.User, locale string) error {
	raw, err := issueEmailToken(h.db, user.ID, models.EmailTokenPurposeVerifyEmail, user.Email, verifyEmailTokenTTL, timeutil.Now())
	if err != nil {
		logger.Errorf("failed to issue verification token for user %d: %v", user.ID, err)
		return err
	}
	m, err := services.VerifyEmailMail(locale, h.cfg.SiteName, user.Email, user.Username, frontendLink(h.cfg.FrontendURL, "/verify-email", raw))
	if err != nil {
		logger.Errorf("failed to build verification email for user %d: %v", user.ID, err)
		return err
	}
	h.mailer.SendAsync(m)
	return nil
}

func (h *UserHandler) sendPasswordResetEmail(user *models.User, locale string) {
	raw, err := issueEmailToken(h.db, user.ID, models.EmailTokenPurposeResetPassword, user.Email, resetPasswordTokenTTL, timeutil.Now())
	if err != nil {
		logger.Errorf("failed to issue password reset token for user %d: %v", user.ID, err)
		return
	}
	m, err := services.ResetPasswordMail(locale, h.cfg.SiteName, user.Email, user.Username, frontendLink(h.cfg.FrontendURL, "/reset-password", raw))
	if err != nil {
		logger.Errorf("failed to build password reset email for user %d: %v", user.ID, err)
		return
	}
	h.mailer.SendAsync(m)
}

// ForgotPassword 发送重置密码邮件
// The response is identical whether or not the account exists, and token
// creation runs in the background, so the endpoint does not reveal which
// emails are registered.
func (h *UserHandler) ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "error.validation", "Validation failed")})
		return
	}
	email := normalizeEmail(req.Email)
	if !isValidReporterEmail(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "validation.email_invalid", "Invalid email format")})
		return
	}
	if !h.allowForgotPassword(c.Request.Context(), reporterIP(c), email) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": tr(c, "auth.forgot_password_rate_limited", "Too many password reset requests. Please try again later.")})
		return
	}

	var user models.User
	err := h.db.Where("LOWER(email) = ?", email).First(&user).Error
	switch {
	case err == nil && user.Status != "banned":
		locale := middleware.GetLocale(c)
		h.mailer.Go("forgot-password", func() { h.sendPasswordResetEmail(&user, locale) })
	case err != nil && !errors.Is(err, gorm.ErrRecordNotFound):
		logger.Errorf("forgot password: user lookup failed: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": tr(c, "auth.reset_link_sent", "If an account exists for that email, we sent a reset link.")})
}

// ResetPassword 通过邮件令牌重置密码
func (h *UserHandler) ResetPassword(c *gin.Context) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "error.validation", "Validation failed")})
		return
	}
	if strings.TrimSpace(req.Token) == "" {
		invalidTokenResponse(c)
		return
	}
	if utf8.RuneCountInString(req.Password) < passwordMinLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "validation.password_too_short", "Password must be at least 6 characters")})
		return
	}
	if len(req.Password) > passwordMaxBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "validation.password_too_long", "Password must be at most 72 bytes")})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "error.hash_password_failed", "Failed to hash password")})
		return
	}

	now := timeutil.Now()
	err = h.db.Transaction(func(tx *gorm.DB) error {
		tok, err := consumeEmailToken(tx, req.Token, models.EmailTokenPurposeResetPassword, now)
		if err != nil {
			return err
		}
		var user models.User
		if err := tx.First(&user, tok.UserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errInvalidEmailToken
			}
			return err
		}
		if user.Status == "banned" || !strings.EqualFold(user.Email, tok.Email) {
			return errInvalidEmailToken
		}
		if err := tx.Model(&models.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{
			"password_hash":       string(hashedPassword),
			"password_changed_at": now,
			"email_verified":      true,
		}).Error; err != nil {
			return err
		}
		// 能收到重置邮件同样证明了邮箱归属
		if err := grantInvitationReward(tx, user.ID); err != nil {
			return err
		}
		return tx.Model(&models.EmailToken{}).
			Where("user_id = ? AND purpose = ? AND used_at IS NULL", user.ID, models.EmailTokenPurposeResetPassword).
			Update("used_at", now).Error
	})
	if errors.Is(err, errInvalidEmailToken) {
		invalidTokenResponse(c)
		return
	}
	if err != nil {
		logger.Errorf("reset password failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "error.internal_server", "Internal server error")})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": tr(c, "auth.password_reset_success", "Your password has been reset. You can now sign in.")})
}

// VerifyEmail 通过邮件令牌验证邮箱
func (h *UserHandler) VerifyEmail(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "error.validation", "Validation failed")})
		return
	}

	var verifiedEmail string
	err := h.db.Transaction(func(tx *gorm.DB) error {
		tok, err := consumeEmailToken(tx, req.Token, models.EmailTokenPurposeVerifyEmail, timeutil.Now())
		if err != nil {
			return err
		}
		var user models.User
		if err := tx.First(&user, tok.UserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return errInvalidEmailToken
			}
			return err
		}
		// A link sent to an old address must not verify a changed one.
		if !strings.EqualFold(user.Email, tok.Email) {
			return errInvalidEmailToken
		}
		if err := tx.Model(&models.User{}).Where("id = ?", user.ID).Update("email_verified", true).Error; err != nil {
			return err
		}
		if err := grantInvitationReward(tx, user.ID); err != nil {
			return err
		}
		verifiedEmail = user.Email
		return nil
	})
	if errors.Is(err, errInvalidEmailToken) {
		invalidTokenResponse(c)
		return
	}
	if err != nil {
		logger.Errorf("verify email failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "error.internal_server", "Internal server error")})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": tr(c, "auth.email_verified", "Your email address has been verified."),
		"email":   verifiedEmail,
	})
}

// verificationRetryAfter returns how many seconds the user must wait before
// another verification email may be sent, or 0 if one is allowed now. The
// issued tokens double as the send log, so this works without Redis.
func (h *UserHandler) verificationRetryAfter(userID uint, now time.Time) (int, error) {
	var sentAt []time.Time
	if err := h.db.Model(&models.EmailToken{}).
		Where("user_id = ? AND purpose = ? AND created_at > ?", userID, models.EmailTokenPurposeVerifyEmail, now.Add(-resendVerificationWindow)).
		Order("created_at DESC").
		Pluck("created_at", &sentAt).Error; err != nil {
		return 0, err
	}
	var wait time.Duration
	if len(sentAt) > 0 {
		if d := sentAt[0].Add(resendVerificationCooldown).Sub(now); d > wait {
			wait = d
		}
	}
	if len(sentAt) >= resendVerificationHourlyLimit {
		oldest := sentAt[resendVerificationHourlyLimit-1]
		if d := oldest.Add(resendVerificationWindow).Sub(now); d > wait {
			wait = d
		}
	}
	if wait <= 0 {
		return 0, nil
	}
	return int(math.Ceil(wait.Seconds())), nil
}

// ResendVerification 重新发送邮箱验证邮件
func (h *UserHandler) ResendVerification(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": tr(c, "error.unauthorized", "Unauthorized")})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": tr(c, "error.user_not_found", "User not found")})
		return
	}
	if user.EmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": tr(c, "auth.already_verified", "Your email address is already verified."),
			"code":  "already_verified",
		})
		return
	}

	retryAfter, err := h.verificationRetryAfter(user.ID, timeutil.Now())
	if err != nil {
		logger.Errorf("resend verification: rate limit lookup failed for user %d: %v", user.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "error.internal_server", "Internal server error")})
		return
	}
	if retryAfter > 0 {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       tr(c, "auth.resend_rate_limited", "Please wait before requesting another verification email."),
			"code":        "rate_limited",
			"retry_after": retryAfter,
		})
		return
	}

	if err := h.sendVerificationEmail(&user, middleware.GetLocale(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "error.internal_server", "Internal server error")})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": tr(c, "auth.verification_sent", "We sent a new verification link to your email.")})
}
