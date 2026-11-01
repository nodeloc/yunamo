package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"opendomain/internal/config"
	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/internal/services"
	"opendomain/pkg/logger"
	"opendomain/pkg/timeutil"
)

type UserHandler struct {
	db     *gorm.DB
	rdb    *redis.Client
	cfg    *config.Config
	mailer *services.Mailer
}

// Login throttling: cap failed attempts per IP and per account within a window.
const (
	loginRateWindow    = 15 * time.Minute
	loginMaxPerIP      = 20
	loginMaxPerAccount = 10
)

// allowLogin attempts fails open when Redis is unavailable (a total login
// outage would be worse than briefly losing the throttle), matching the
// behavior of the other rate limiters in this package.
func (h *UserHandler) allowLogin(ctx context.Context, ip, email string) bool {
	if h.rdb == nil {
		return true
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	perIP, err := incrRateWindow(rctx, h.rdb, "login:rate:ip:"+ip, loginRateWindow)
	if err != nil {
		logger.Warnf("login rate limit: redis unavailable, allowing request: %v", err)
		return true
	}
	perAccount, err := incrRateWindow(rctx, h.rdb, "login:rate:acct:"+hashEmailToken(strings.ToLower(email)), loginRateWindow)
	if err != nil {
		logger.Warnf("login rate limit: redis unavailable, allowing request: %v", err)
		return true
	}
	return perIP <= loginMaxPerIP && perAccount <= loginMaxPerAccount
}

func NewUserHandler(db *gorm.DB, rdb *redis.Client, cfg *config.Config, mailer *services.Mailer) *UserHandler {
	return &UserHandler{db: db, rdb: rdb, cfg: cfg, mailer: mailer}
}

// Register 用户注册
// @Summary 用户注册
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body models.UserRegisterRequest true "注册信息"
// @Success 200 {object} models.UserResponse
// @Router /api/auth/register [post]
func (h *UserHandler) Register(c *gin.Context) {
	var req models.UserRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": middleware.T(c, "error.validation")})
		return
	}

	// 检查用户名是否已存在
	var existingUser models.User
	if err := h.db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": middleware.T(c, "error.username_exists")})
		return
	}

	// 检查邮箱是否已存在
	if err := h.db.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": middleware.T(c, "error.email_exists")})
		return
	}

	// 哈希密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": middleware.T(c, "error.hash_password_failed")})
		return
	}

	// 生成邀请码
	inviteCode, err := generateInviteCode()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": middleware.T(c, "error.generate_invite_code_failed")})
		return
	}

	// 创建用户 (从 settings 读取默认配额)
	defaultQuota := GetQuotaForLevel(h.db, "normal")
	user := &models.User{
		Username:      req.Username,
		Email:         req.Email,
		EmailVerified: false,
		PasswordHash:  string(hashedPassword),
		InviteCode:    inviteCode,
		UserLevel:     "normal",
		DomainQuota:   defaultQuota,
		Status:        "active",
	}

	// 开始事务处理邀请码和奖励
	tx := h.db.Begin()

	// 处理邀请码
	var inviterID *uint
	if req.InviteCode != nil && *req.InviteCode != "" {
		var inviter models.User
		if err := tx.Where("invite_code = ?", *req.InviteCode).First(&inviter).Error; err == nil {
			user.InvitedBy = &inviter.ID
			inviterID = &inviter.ID
		}
	}

	// 创建用户
	if err := tx.Create(user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": middleware.T(c, "error.create_user_failed")})
		return
	}

	// 如果有邀请人，处理邀请奖励
	if inviterID != nil {
		// 创建邀请记录
		invitation := &models.Invitation{
			InviterID:   *inviterID,
			InviteeID:   user.ID,
			InviteCode:  *req.InviteCode,
			RewardGiven: true,
			RewardType:  "quota_increase",
			RewardValue: "inviter: +1 quota, invitee: +1 quota",
		}

		if err := tx.Create(invitation).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": middleware.T(c, "error.internal_server")})
			return
		}

		// 更新邀请人数据：增加配额和邀请统计
		if err := tx.Model(&models.User{}).Where("id = ?", inviterID).Updates(map[string]interface{}{
			"domain_quota":       gorm.Expr("domain_quota + ?", 1),
			"total_invites":      gorm.Expr("total_invites + ?", 1),
			"successful_invites": gorm.Expr("successful_invites + ?", 1),
		}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": middleware.T(c, "error.internal_server")})
			return
		}

		// 给新用户增加额外配额（邀请奖励）
		user.DomainQuota += 1
		if err := tx.Save(user).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": middleware.T(c, "error.internal_server")})
			return
		}
	}

	tx.Commit()

	verificationSent := h.sendVerificationEmail(user, middleware.GetLocale(c)) == nil

	c.JSON(http.StatusOK, gin.H{
		"message":                 middleware.T(c, "success.user_created"),
		"user":                    user.ToResponse(),
		"email_verification_sent": verificationSent,
	})
}

// Login 用户登录
// @Summary 用户登录
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body models.UserLoginRequest true "登录信息"
// @Success 200 {object} map[string]interface{}
// @Router /api/auth/login [post]
func (h *UserHandler) Login(c *gin.Context) {
	var req models.UserLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": middleware.T(c, "error.validation")})
		return
	}

	// 登录频率限制（按 IP + 账号），防止暴力破解/撞库
	if !h.allowLogin(c.Request.Context(), reporterIP(c), req.Email) {
		c.Header("Retry-After", strconv.Itoa(int(loginRateWindow.Seconds())))
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": middleware.T(c, "auth.login_rate_limited"),
			"code":  "rate_limited",
		})
		return
	}

	// 查找用户
	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": middleware.T(c, "error.invalid_credentials")})
		return
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": middleware.T(c, "error.invalid_credentials")})
		return
	}

	// 检查账号状态
	if user.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": middleware.T(c, "error.forbidden")})
		return
	}

	// 更新最后登录信息
	now := timeutil.Now()
	clientIP := c.ClientIP()
	user.LastLoginAt = &now
	user.LastLoginIP = &clientIP
	h.db.Save(&user)

	// 生成 JWT token
	token, err := generateToken(&user, h.cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": middleware.T(c, "error.internal_server")})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": middleware.T(c, "success.login"),
		"token":   token,
		"user":    user.ToResponse(),
	})
}

// GetProfile 获取用户信息
// @Summary 获取用户信息
// @Tags User
// @Produce json
// @Success 200 {object} models.UserResponse
// @Router /api/user/profile [get]
// @Security Bearer
func (h *UserHandler) GetProfile(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

// UpdateProfile 更新用户信息
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var req struct {
		Username *string `json:"username"`
		Avatar   *string `json:"avatar"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Username != nil {
		user.Username = *req.Username
	}
	if req.Avatar != nil {
		user.Avatar = req.Avatar
	}

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, user.ToResponse())
}

// ListUsers 管理员：获取用户列表
func (h *UserHandler) ListUsers(c *gin.Context) {
	search := c.Query("search")
	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	query := h.db.Model(&models.User{})

	// 搜索功能：支持按用户名、邮箱、邀请码搜索
	if search != "" {
		query = query.Where("username LIKE ? OR email LIKE ? OR invite_code LIKE ?",
			"%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count users"})
		return
	}

	// 分页查询
	var users []models.User
	offset := (page - 1) * pageSize
	if err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	responses := make([]*models.UserResponse, len(users))
	for i, user := range users {
		responses[i] = user.ToResponse()
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize != 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"users": responses,
		"pagination": gin.H{
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"total_pages": totalPages,
		},
	})
}

// AdminUpdateUserStatus 管理员：更新用户状态
func (h *UserHandler) AdminUpdateUserStatus(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Status string `json:"status" binding:"required,oneof=active frozen banned"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 不能修改管理员状态
	if user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot modify admin user status"})
		return
	}

	if err := h.db.Model(&user).Update("status", req.Status).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user status"})
		return
	}

	user.Status = req.Status
	c.JSON(http.StatusOK, gin.H{
		"message": "User status updated",
		"user":    user.ToResponse(),
	})
}

// AdminUpdateUser 管理员：编辑用户信息
func (h *UserHandler) AdminUpdateUser(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Username *string `json:"username"`
		Email    *string `json:"email"`
		Password *string `json:"password"`
		IsAdmin  *bool   `json:"is_admin"`
		Status   *string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	updates := map[string]interface{}{}

	if req.Username != nil && *req.Username != "" {
		var existing models.User
		if err := h.db.Where("username = ? AND id != ?", *req.Username, user.ID).First(&existing).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username already taken"})
			return
		}
		updates["username"] = *req.Username
	}

	if req.Email != nil && *req.Email != "" {
		var existing models.User
		if err := h.db.Where("email = ? AND id != ?", *req.Email, user.ID).First(&existing).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email already taken"})
			return
		}
		updates["email"] = *req.Email
	}

	if req.Password != nil && *req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		updates["password_hash"] = string(hashedPassword)
	}

	if req.IsAdmin != nil {
		updates["is_admin"] = *req.IsAdmin
	}

	if req.Status != nil {
		updates["status"] = *req.Status
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	if err := h.db.Model(&user).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	h.db.First(&user, userID)
	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
		"user":    user.ToResponse(),
	})
}

// AdminDeleteUser 管理员：删除用户
func (h *UserHandler) AdminDeleteUser(c *gin.Context) {
	userID := c.Param("id")

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 防止删除管理员账户
	if user.IsAdmin {
		c.JSON(http.StatusForbidden, gin.H{"error": "Cannot delete admin users"})
		return
	}

	// 软删除用户
	if err := h.db.Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

// ChangePassword 用户修改密码
func (h *UserHandler) ChangePassword(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 验证当前密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Current password is incorrect"})
		return
	}

	// 生成新密码哈希
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	// 更新密码
	if err := h.db.Model(&user).Update("password_hash", string(hashedPassword)).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// generateToken 生成 JWT token
func generateToken(user *models.User, cfg *config.Config) (string, error) {
	claims := &middleware.Claims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		IsAdmin:  user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(timeutil.Now().Add(time.Duration(cfg.JWT.ExpiresIn) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(timeutil.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(cfg.JWT.Secret))
}

// generateInviteCode 生成邀请码
func generateInviteCode() (string, error) {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
