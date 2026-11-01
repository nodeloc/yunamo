package middleware

import (
	"net/http"
	"strings"

	"opendomain/internal/config"
	"opendomain/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// Claims JWT 声明
type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
	jwt.RegisteredClaims
}

// AuthMiddleware JWT 认证中间件
//
// 除验签外还会查询数据库：被封禁/冻结/删除的账号，其旧 token 在过期前也应
// 立即失效；管理员权限以数据库当前值为准，避免降权后旧 token 仍可操作后台。
func AuthMiddleware(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": T(c, "error.unauthorized")})
			c.Abort()
			return
		}

		// Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": T(c, "error.unauthorized")})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// 解析 token，并限定签名算法为 HS256，防止算法混淆
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWT.Secret), nil
		}, jwt.WithValidMethods([]string{"HS256"}))

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": T(c, "error.unauthorized")})
			c.Abort()
			return
		}

		// 校验账号仍然存在且处于激活状态
		var user models.User
		if err := db.Select("id", "is_admin", "status").First(&user, claims.UserID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": T(c, "error.unauthorized")})
			c.Abort()
			return
		}
		if user.Status != "active" {
			c.JSON(http.StatusForbidden, gin.H{"error": T(c, "error.forbidden")})
			c.Abort()
			return
		}

		// 设置用户信息到上下文
		c.Set("user_id", user.ID)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("is_admin", user.IsAdmin)

		c.Next()
	}
}

// AdminMiddleware 管理员权限中间件
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get("is_admin")
		if !exists || !isAdmin.(bool) {
			c.JSON(http.StatusForbidden, gin.H{"error": T(c, "error.permission_denied")})
			c.Abort()
			return
		}
		c.Next()
	}
}

// GetUserID 从上下文获取用户 ID
func GetUserID(c *gin.Context) (uint, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return 0, false
	}
	return userID.(uint), true
}
