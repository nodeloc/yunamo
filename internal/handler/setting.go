package handler

import (
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"opendomain/internal/config"
	"opendomain/internal/models"
	"opendomain/pkg/timeutil"
)

var startTime = timeutil.Now()

type SettingHandler struct {
	db  *gorm.DB
	rdb *redis.Client
	cfg *config.Config
}

func NewSettingHandler(db *gorm.DB, cfg *config.Config) *SettingHandler {
	return &SettingHandler{db: db, cfg: cfg}
}

func NewSettingHandlerWithRedis(db *gorm.DB, rdb *redis.Client, cfg *config.Config) *SettingHandler {
	return &SettingHandler{db: db, rdb: rdb, cfg: cfg}
}

// GetSettings 获取所有系统设置 (admin only)
func (h *SettingHandler) GetSettings(c *gin.Context) {
	var settings []models.SystemSetting
	if err := h.db.Find(&settings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

// UpdateSetting 更新单个设置 (admin only)
func (h *SettingHandler) UpdateSetting(c *gin.Context) {
	key := c.Param("key")

	var req struct {
		Value string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var setting models.SystemSetting
	if err := h.db.Where("setting_key = ?", key).First(&setting).Error; err != nil {
		// 不存在则创建
		setting = models.SystemSetting{
			SettingKey:   key,
			SettingValue: req.Value,
		}
		if err := h.db.Create(&setting).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create setting"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"setting": setting})
		return
	}

	setting.SettingValue = req.Value
	if err := h.db.Save(&setting).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update setting"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"setting": setting})
}

// GetSystemInfo 获取系统信息 (admin only)
func (h *SettingHandler) GetSystemInfo(c *gin.Context) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(startTime)

	// 统计数据
	var userCount, domainCount, orderCount int64
	h.db.Model(&models.User{}).Count(&userCount)
	h.db.Model(&models.Domain{}).Count(&domainCount)
	h.db.Model(&models.Order{}).Count(&orderCount)

	// Redis 状态
	redisStatus := "disconnected"
	if h.rdb != nil {
		if err := h.rdb.Ping(c.Request.Context()).Err(); err == nil {
			redisStatus = "connected"
		}
	}

	// DB 状态
	dbStatus := "connected"
	sqlDB, err := h.db.DB()
	if err != nil || sqlDB.Ping() != nil {
		dbStatus = "disconnected"
	}

	c.JSON(http.StatusOK, gin.H{
		"system": gin.H{
			"version":     "v1.0.0",
			"environment": h.cfg.Env,
			"go_version":  runtime.Version(),
			"goroutines":  runtime.NumGoroutine(),
			"os":          runtime.GOOS,
			"arch":        runtime.GOARCH,
		},
		"site": gin.H{
			"name":        h.cfg.SiteName,
			"description": h.cfg.SiteDescription,
		},
		"uptime": gin.H{
			"seconds": int(uptime.Seconds()),
			"human":   formatDuration(uptime),
		},
		"memory": gin.H{
			"alloc_mb":       fmt.Sprintf("%.1f", float64(memStats.Alloc)/1024/1024),
			"total_alloc_mb": fmt.Sprintf("%.1f", float64(memStats.TotalAlloc)/1024/1024),
			"sys_mb":         fmt.Sprintf("%.1f", float64(memStats.Sys)/1024/1024),
			"gc_cycles":      memStats.NumGC,
		},
		"stats": gin.H{
			"users":   userCount,
			"domains": domainCount,
			"orders":  orderCount,
		},
		"services": gin.H{
			"database": dbStatus,
			"redis":    redisStatus,
		},
		"dns": gin.H{
			"ns1": h.cfg.DNS.DefaultNS1,
			"ns2": h.cfg.DNS.DefaultNS2,
		},
		"payment": gin.H{
			"configured": h.cfg.Payment.NodelocPaymentID != "",
			"test_mode":  h.cfg.Payment.IsTestMode,
		},
		"email": gin.H{
			"configured": h.cfg.Email.Host != "",
			"host":       h.cfg.Email.Host,
			"port":       h.cfg.Email.Port,
		},
		"oauth": gin.H{
			"github":  h.cfg.OAuth.GithubClientID != "",
			"google":  h.cfg.OAuth.GoogleClientID != "",
			"nodeloc": h.cfg.OAuth.NodelocClientID != "",
		},
	})
}

// GetDashboardStats 管理员：获取仪表板统计数据
func (h *SettingHandler) GetDashboardStats(c *gin.Context) {
	// 统计用户总数
	var userCount int64
	h.db.Model(&models.User{}).Count(&userCount)

	// 统计域名总数
	var domainCount int64
	h.db.Model(&models.Domain{}).Count(&domainCount)

	// 统计总收入（已支付订单的总金额）
	var totalRevenue float64
	h.db.Model(&models.Order{}).
		Where("status = ?", "paid").
		Select("COALESCE(SUM(final_price), 0)").
		Scan(&totalRevenue)

	c.JSON(http.StatusOK, gin.H{
		"total_users":   userCount,
		"total_domains": domainCount,
		"total_revenue": totalRevenue,
	})
}

// GetPublicStats 公开接口：返回站点统计数据（无需认证）
func (h *SettingHandler) GetPublicStats(c *gin.Context) {
	var totalDomains int64
	h.db.Model(&models.Domain{}).Where("status != ?", "deleted").Count(&totalDomains)

	var totalUsers int64
	h.db.Model(&models.User{}).Count(&totalUsers)

	c.JSON(http.StatusOK, gin.H{
		"total_domains": totalDomains,
		"total_users":   totalUsers,
	})
}

// GetPublicSiteConfig 公开接口：返回站点基本配置（无需认证）
func (h *SettingHandler) GetPublicSiteConfig(c *gin.Context) {
	// allow_password_register 从数据库读取
	var setting models.SystemSetting
	allowRegister := true
	if err := h.db.Where("setting_key = ?", "allow_password_register").First(&setting).Error; err == nil {
		allowRegister = setting.SettingValue != "false"
	}

	// 获取货币符号设置
	currencySymbol := models.GetSettingValue(h.db, "currency_symbol", "NL")

	c.JSON(http.StatusOK, gin.H{
		"site_name":               h.cfg.SiteName,
		"site_description":        h.cfg.SiteDescription,
		"allow_password_register": allowRegister,
		"currency_symbol":         currencySymbol,
		"oauth": gin.H{
			"github":  h.cfg.OAuth.GithubClientID != "",
			"google":  h.cfg.OAuth.GoogleClientID != "",
			"nodeloc": h.cfg.OAuth.NodelocClientID != "",
		},
	})
}

// ClearCache 清除 Redis 缓存
func (h *SettingHandler) ClearCache(c *gin.Context) {
	if h.rdb == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Redis not available"})
		return
	}

	if err := h.rdb.FlushDB(c.Request.Context()).Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear cache"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Cache cleared successfully"})
}

// formatDuration 将 time.Duration 格式化为人类可读的字符串
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// GetQuotaForLevel 根据等级从 settings 表读取 quota 值
func GetQuotaForLevel(db *gorm.DB, level string) int {
	key := fmt.Sprintf("quota_%s", level)
	var setting models.SystemSetting
	if err := db.Where("setting_key = ?", key).First(&setting).Error; err != nil {
		defaults := map[string]int{
			"normal":  2,
			"basic":   3,
			"member":  5,
			"regular": 10,
			"leader":  20,
		}
		if v, ok := defaults[level]; ok {
			return v
		}
		return 2
	}

	quota, err := strconv.Atoi(setting.SettingValue)
	if err != nil {
		return 2
	}
	return quota
}

// TrustLevelToUserLevel 将 NodeLoc trust_level 映射为用户等级
func TrustLevelToUserLevel(trustLevel int) string {
	switch trustLevel {
	case 0:
		return "normal"
	case 1:
		return "basic"
	case 2:
		return "member"
	case 3:
		return "regular"
	case 4:
		return "leader"
	default:
		if trustLevel > 4 {
			return "leader"
		}
		return "normal"
	}
}
