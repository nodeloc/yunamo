package handler

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"opendomain/internal/config"
	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/pkg/powerdns"
	"opendomain/pkg/timeutil"
)

type DomainHandler struct {
	db        *gorm.DB
	cfg       *config.Config
	pdns      *powerdns.Client
	cpHandler *CyberPanelHandler
}

func NewDomainHandler(db *gorm.DB, cfg *config.Config) *DomainHandler {
	return &DomainHandler{
		db:   db,
		cfg:  cfg,
		pdns: powerdns.NewClient(cfg.PowerDNS.APIURL, cfg.PowerDNS.APIKey),
	}
}

// SetCyberPanelHandler 注入 CyberPanel 处理器，实现域名联动
func (h *DomainHandler) SetCyberPanelHandler(cp *CyberPanelHandler) {
	h.cpHandler = cp
}

// ListRootDomains 获取根域名列表
// @Summary 获取根域名列表
// @Tags Public
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/public/root-domains [get]
func (h *DomainHandler) ListRootDomains(c *gin.Context) {
	var rootDomains []models.RootDomain
	if err := h.db.Where("is_active = ?", true).Order("priority DESC, id ASC").Find(&rootDomains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": middleware.T(c, "error.internal_server")})
		return
	}

	c.JSON(http.StatusOK, gin.H{"root_domains": rootDomains})
}

// SearchDomain 搜索域名可用性
// @Summary 搜索域名可用性
// @Tags Domain
// @Produce json
// @Param subdomain query string true "子域名"
// @Param root_domain_id query int true "根域名ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/domains/search [get]
// @Security Bearer
func (h *DomainHandler) SearchDomain(c *gin.Context) {
	var req models.DomainSearchRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": middleware.T(c, "error.validation")})
		return
	}

	// 获取根域名
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, req.RootDomainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": middleware.T(c, "error.root_domain_not_found")})
		return
	}

	if !rootDomain.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"error": middleware.T(c, "error.root_domain_inactive")})
		return
	}

	// 验证子域名格式
	if !isValidSubdomain(req.Subdomain) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":     middleware.T(c, "error.domain_invalid"),
			"available": false,
		})
		return
	}

	// 检查长度
	if len(req.Subdomain) < rootDomain.MinLength || len(req.Subdomain) > rootDomain.MaxLength {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Subdomain length must be between %d and %d characters",
				rootDomain.MinLength, rootDomain.MaxLength),
			"available": false,
		})
		return
	}

	// 检查黑名单
	if isBlacklisted(h.db, req.Subdomain) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":     "This subdomain is reserved",
			"available": false,
		})
		return
	}

	fullDomain := fmt.Sprintf("%s.%s", req.Subdomain, rootDomain.Domain)

	// 检查是否已被注册（仅检查未软删除的记录，软删除的域名可重新注册）
	var existingDomain models.Domain
	err := h.db.Where("full_domain = ?", fullDomain).First(&existingDomain).Error

	available := err == gorm.ErrRecordNotFound

	reserved := false

	response := gin.H{
		"available":   available,
		"subdomain":   req.Subdomain,
		"root_domain": rootDomain.Domain,
		"full_domain": fullDomain,
	}

	if reserved {
		response["reserved"] = true
		response["message"] = "This domain is reserved and can only be activated by syncing from FOSSBilling"
	}

	if !available && !reserved {
		response["domain_info"] = gin.H{
			"status":         existingDomain.Status,
			"registered_at":  existingDomain.RegisteredAt,
			"expires_at":     existingDomain.ExpiresAt,
			"suspended_at":   existingDomain.SuspendedAt,
			"suspend_reason": existingDomain.SuspendReason,
		}
	}

	c.JSON(http.StatusOK, response)
}

// WhoisDomain 查询域名 WHOIS 信息（公开）
func (h *DomainHandler) WhoisDomain(c *gin.Context) {
	fullDomain := c.Param("domain")
	if fullDomain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}

	var domain models.Domain
	if err := h.db.Where("full_domain = ?", fullDomain).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	now := time.Now()

	// 计算待挂起/待删除剩余天数
	var daysSinceFailure float64
	var daysUntilSuspension *int
	var daysUntilDeletion *int

	if domain.FirstFailedAt != nil {
		daysSinceFailure = now.Sub(*domain.FirstFailedAt).Hours() / 24
		if domain.Status != "suspended" {
			d := 7 - int(daysSinceFailure)
			if d < 0 {
				d = 0
			}
			daysUntilSuspension = &d
		} else {
			d := 30 - int(daysSinceFailure)
			if d < 0 {
				d = 0
			}
			daysUntilDeletion = &d
		}
	}

	// 查询扫描摘要
	var scanInfo gin.H
	var summary models.DomainScanSummary
	if err := h.db.Where("domain_id = ?", domain.ID).First(&summary).Error; err == nil {
		var uptime float64
		if summary.TotalScans > 0 {
			uptime = float64(summary.SuccessfulScans) / float64(summary.TotalScans) * 100
		}
		scanInfo = gin.H{
			"overall_health":       summary.OverallHealth,
			"http_status":          summary.HTTPStatus,
			"dns_status":           summary.DNSStatus,
			"ssl_status":           summary.SSLStatus,
			"safe_browsing_status": summary.SafeBrowsingStatus,
			"virustotal_status":    summary.VirusTotalStatus,
			"uptime_percentage":    uptime,
			"total_scans":          summary.TotalScans,
			"successful_scans":     summary.SuccessfulScans,
			"last_scanned_at":      summary.LastScannedAt,
		}
	}

	// 解析 nameservers JSON 数组
	var nameservers []string
	if domain.Nameservers != "" {
		_ = json.Unmarshal([]byte(domain.Nameservers), &nameservers)
	}

	c.JSON(http.StatusOK, gin.H{
		"full_domain":           domain.FullDomain,
		"status":                domain.Status,
		"registered_at":         domain.RegisteredAt,
		"expires_at":            domain.ExpiresAt,
		"suspended_at":          domain.SuspendedAt,
		"suspend_reason":        domain.SuspendReason,
		"first_failed_at":       domain.FirstFailedAt,
		"days_until_suspension": daysUntilSuspension,
		"days_until_deletion":   daysUntilDeletion,
		"nameservers":           nameservers,
		"scan":                  scanInfo,
	})
}

// RegisterDomain 注册域名（仅适用于免费域名）
// @Summary 注册域名
// @Tags Domain
// @Accept json
// @Produce json
// @Param request body models.DomainRegisterRequest true "注册信息"
// @Success 200 {object} models.DomainResponse
// @Router /api/domains [post]
// @Security Bearer
func (h *DomainHandler) RegisterDomain(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// 获取用户信息
	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	if !requireVerifiedEmail(c, &user) {
		return
	}

	var req models.DomainRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 获取根域名
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, req.RootDomainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}

	if !rootDomain.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Root domain is not active"})
		return
	}

	// 检查用户等级是否满足根域名要求
	if userLevelOrder(user.UserLevel) < userLevelOrder(rootDomain.MinUserLevel) {
		c.JSON(http.StatusForbidden, gin.H{
			"error":          "Your account level is too low to register under this domain",
			"required_level": rootDomain.MinUserLevel,
			"your_level":     user.UserLevel,
		})
		return
	}

	// 检查是否为付费域名
	if !rootDomain.IsFree {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":            "This domain requires payment. Please create an order first.",
			"requires_payment": true,
			"price_per_year":   rootDomain.PricePerYear,
			"lifetime_price":   rootDomain.LifetimePrice,
		})
		return
	}

	// 验证域名
	if !isValidSubdomain(req.Subdomain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid subdomain format"})
		return
	}

	if isBlacklisted(h.db, req.Subdomain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This subdomain is reserved"})
		return
	}

	fullDomain := fmt.Sprintf("%s.%s", req.Subdomain, rootDomain.Domain)

	// 检查是否已存在活跃记录（未软删除）
	var existingDomain models.Domain
	if err := h.db.Where("full_domain = ?", fullDomain).First(&existingDomain).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Domain already registered"})
		return
	}

	// 检查是否存在软删除记录（唯一约束仍生效，需在事务内恢复而非新建）
	var softDeletedDomain models.Domain
	hasSoftDeleted := h.db.Unscoped().Where("full_domain = ? AND deleted_at IS NOT NULL", fullDomain).First(&softDeletedDomain).Error == nil

	// 检查用户配额
	var userDomainCount int64
	h.db.Model(&models.Domain{}).Where("user_id = ? AND status = ?", userID, "active").Count(&userDomainCount)

	var usedCoupon *models.Coupon
	quotaExceeded := int(userDomainCount) >= user.DomainQuota

	// 如果配额超限，检查优惠券
	if quotaExceeded {
		if req.CouponCode == nil || *req.CouponCode == "" {
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "Domain quota exceeded. Please use a coupon or purchase a domain.",
				"quota_exceeded": true,
			})
			return
		}

		// 查找优惠券
		var coupon models.Coupon
		if err := h.db.Where("UPPER(code) = UPPER(?)", *req.CouponCode).First(&coupon).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Coupon not found"})
			return
		}

		// 验证优惠券
		if err := h.validateCouponForFreeRegistration(&coupon, userID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// 只接受 quota_increase 类型
		if coupon.DiscountType != "quota_increase" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "This coupon type cannot be used for free domain registration",
			})
			return
		}

		usedCoupon = &coupon
	}

	// 开始事务注册域名
	err := h.db.Transaction(func(tx *gorm.DB) error {
		now := timeutil.Now()
		var domain *models.Domain

		if hasSoftDeleted {
			// 恢复软删除记录并重新分配给当前用户
			updates := map[string]interface{}{
				"user_id":                 userID,
				"root_domain_id":          req.RootDomainID,
				"subdomain":               req.Subdomain,
				"status":                  "active",
				"registered_at":           now,
				"expires_at":              now.AddDate(1, 0, 0),
				"auto_renew":              false,
				"nameservers":             rootDomain.Nameservers,
				"use_default_nameservers": rootDomain.UseDefaultNameservers,
				"dns_synced":              false,
				"dns_sync_error":          nil,
				"first_failed_at":         nil,
				"suspended_at":            nil,
				"suspend_reason":          nil,
				"deleted_at":              nil,
			}
			if err := tx.Unscoped().Model(&softDeletedDomain).Updates(updates).Error; err != nil {
				return err
			}
			domain = &softDeletedDomain
		} else {
			// 创建新域名记录
			domain = &models.Domain{
				UserID:                userID,
				RootDomainID:          req.RootDomainID,
				Subdomain:             req.Subdomain,
				FullDomain:            fullDomain,
				Status:                "active",
				RegisteredAt:          now,
				ExpiresAt:             now.AddDate(1, 0, 0), // 1 年后过期
				AutoRenew:             false,
				Nameservers:           rootDomain.Nameservers,
				UseDefaultNameservers: rootDomain.UseDefaultNameservers,
				DNSSynced:             false,
			}
			if err := tx.Create(domain).Error; err != nil {
				return err
			}
		}

		// 如果使用了优惠券，记录使用
		if usedCoupon != nil {
			usage := &models.CouponUsage{
				CouponID: usedCoupon.ID,
				UserID:   userID,
				DomainID: &domain.ID,
			}
			if err := tx.Create(usage).Error; err != nil {
				return err
			}

			// 更新优惠券使用次数
			if err := tx.Model(&models.Coupon{}).
				Where("id = ?", usedCoupon.ID).
				UpdateColumn("used_count", gorm.Expr("used_count + ?", 1)).Error; err != nil {
				return err
			}

			// 如果是 quota_increase 类型，更新用户配额
			if usedCoupon.DiscountType == "quota_increase" && usedCoupon.QuotaIncrease > 0 {
				if err := tx.Model(&user).
					UpdateColumn("domain_quota", gorm.Expr("domain_quota + ?", usedCoupon.QuotaIncrease)).Error; err != nil {
					return err
				}
			}
		}

		// 更新根域名注册计数
		if err := tx.Model(&rootDomain).
			UpdateColumn("registration_count", gorm.Expr("registration_count + ?", 1)).Error; err != nil {
			return err
		}

		// 重新加载域名关联数据
		return tx.Preload("RootDomain").First(domain, domain.ID).Error
	})

	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "Domain already registered"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register domain"})
		}
		return
	}

	// 获取最新的域名数据
	var domain models.Domain
	h.db.Preload("RootDomain").Where("full_domain = ?", fullDomain).First(&domain)

	// 在 PowerDNS 中配置域名
	if domain.RootDomain != nil {
		var nameservers []string
		if err := json.Unmarshal([]byte(domain.Nameservers), &nameservers); err == nil {
			// 如果使用默认 NS 或自定义 NS，都调用此函数进行配置
			go h.updateDomainNSRecordsInPowerDNS(&domain, nameservers, domain.UseDefaultNameservers)
		}
	}

	response := gin.H{
		"message": "Domain registered successfully",
		"domain":  domain.ToResponse(),
	}

	if usedCoupon != nil {
		response["coupon_applied"] = true
		response["coupon_code"] = usedCoupon.Code
	}

	c.JSON(http.StatusOK, response)
}

// validateCouponForFreeRegistration 验证免费注册时的优惠券
func (h *DomainHandler) validateCouponForFreeRegistration(coupon *models.Coupon, userID uint) error {
	now := timeutil.Now()

	// 检查是否激活
	if !coupon.IsActive {
		return fmt.Errorf("coupon is not active")
	}

	// 检查有效期
	if now.Before(coupon.ValidFrom) {
		return fmt.Errorf("coupon not yet valid")
	}
	if coupon.ValidUntil != nil && now.After(*coupon.ValidUntil) {
		return fmt.Errorf("coupon has expired")
	}

	// 检查使用次数
	if coupon.MaxUses > 0 && coupon.UsedCount >= coupon.MaxUses {
		return fmt.Errorf("coupon usage limit reached")
	}

	// 检查用户是否已使用（quota 类型的优惠券每人只能用一次）
	var usage models.CouponUsage
	if err := h.db.Where("coupon_id = ? AND user_id = ?", coupon.ID, userID).
		First(&usage).Error; err == nil {
		return fmt.Errorf("you have already used this coupon")
	}

	return nil
}

// ListMyDomains 获取我的域名列表
// @Summary 获取我的域名列表
// @Tags Domain
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/domains [get]
// @Security Bearer
func (h *DomainHandler) ListMyDomains(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var domains []models.Domain
	if err := h.db.Preload("RootDomain").Where("user_id = ?", userID).
		Order("created_at DESC").Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch domains"})
		return
	}

	// 获取域名的扫描摘要
	domainIDs := make([]uint, len(domains))
	for i, domain := range domains {
		domainIDs[i] = domain.ID
	}

	var summaries []models.DomainScanSummary
	if len(domainIDs) > 0 {
		h.db.Where("domain_id IN ?", domainIDs).Find(&summaries)
	}

	// 创建域名ID到扫描摘要的映射
	summaryMap := make(map[uint]*models.DomainScanSummary)
	for i := range summaries {
		summaryMap[summaries[i].DomainID] = &summaries[i]
	}

	responses := make([]map[string]interface{}, len(domains))
	for i, domain := range domains {
		resp := domain.ToResponse()
		domainMap := map[string]interface{}{
			"id":                      resp.ID,
			"user_id":                 resp.UserID,
			"root_domain_id":          resp.RootDomainID,
			"subdomain":               resp.Subdomain,
			"full_domain":             resp.FullDomain,
			"status":                  resp.Status,
			"registered_at":           resp.RegisteredAt,
			"expires_at":              resp.ExpiresAt,
			"auto_renew":              resp.AutoRenew,
			"nameservers":             resp.Nameservers,
			"use_default_nameservers": resp.UseDefaultNameservers,
			"dns_synced":              resp.DNSSynced,
			"first_failed_at":         resp.FirstFailedAt,
			"suspended_at":            resp.SuspendedAt,
			"suspend_reason":          resp.SuspendReason,
			"root_domain":             resp.RootDomain,
		}

		// 添加扫描状态
		if summary, ok := summaryMap[domain.ID]; ok {
			domainMap["scan_summary"] = map[string]interface{}{
				"overall_health":       summary.OverallHealth,
				"http_status":          summary.HTTPStatus,
				"dns_status":           summary.DNSStatus,
				"ssl_status":           summary.SSLStatus,
				"safe_browsing_status": summary.SafeBrowsingStatus,
				"virustotal_status":    summary.VirusTotalStatus,
				"last_scanned_at":      summary.LastScannedAt,
				"total_scans":          summary.TotalScans,
				"successful_scans":     summary.SuccessfulScans,
			}
			if summary.TotalScans > 0 {
				uptime := float64(summary.SuccessfulScans) / float64(summary.TotalScans) * 100
				domainMap["scan_summary"].(map[string]interface{})["uptime_percentage"] = uptime
			}
		} else {
			domainMap["scan_summary"] = nil
		}

		responses[i] = domainMap
	}

	c.JSON(http.StatusOK, gin.H{"domains": responses})
}

// GetDomain 获取域名详情
func (h *DomainHandler) GetDomain(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("id")

	var domain models.Domain
	if err := h.db.Preload("RootDomain").First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	// 验证所有权
	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	c.JSON(http.StatusOK, domain.ToResponse())
}

// dnssecKeyView 将 PowerDNS 密钥转换为前端展示格式（仅 active+published）
func dnssecKeyView(keys []powerdns.CryptoKey) []interface{} {
	out := []interface{}{}
	for _, k := range keys {
		if k.Active && k.Published {
			out = append(out, gin.H{
				"id":        k.ID,
				"keytype":   k.KeyType,
				"algorithm": k.Algorithm,
				"bits":      k.Bits,
				"dnskey":    k.DNSKey,
				"ds":        k.DS,
			})
		}
	}
	return out
}

// domainDNSSECStatus 汇总子域名的 DNSSEC 信任链状态：
// 子 zone 是否签名、父 zone 是否签名、父 zone 中是否发布了与当前密钥一致的 DS。
func (h *DomainHandler) domainDNSSECStatus(domain *models.Domain) gin.H {
	status := gin.H{
		"enabled":       false,
		"keys":          []interface{}{},
		"parent_zone":   "",
		"parent_signed": false,
		"ds_published":  false,
		"chain_valid":   false,
	}
	if domain.RootDomain != nil {
		status["parent_zone"] = domain.RootDomain.Domain
		if parent, err := h.pdns.GetZoneInfo(domain.RootDomain.Domain); err == nil {
			status["parent_signed"] = parent.DNSsec
		}
	}

	// Custom nameservers sign the zone elsewhere; all we hold is the DS the
	// owner asked us to publish at the delegation point.
	if !domain.UseDefaultNameservers {
		status["custom_ns"] = true
		dsRecords := []string{}
		if domain.RootDomain != nil {
			if published, err := h.pdns.GetRRset(domain.RootDomain.Domain, domain.FullDomain, "DS"); err == nil {
				for _, r := range published {
					if !r.Disabled {
						dsRecords = append(dsRecords, r.Content)
					}
				}
			}
		}
		status["ds_records"] = dsRecords
		status["enabled"] = len(dsRecords) > 0
		status["ds_published"] = len(dsRecords) > 0
		status["chain_valid"] = len(dsRecords) > 0 && status["parent_signed"] == true
		return status
	}

	zone, err := h.pdns.GetZoneInfo(domain.FullDomain)
	if err != nil || !zone.DNSsec {
		return status
	}
	status["enabled"] = true

	cryptoKeys, err := h.pdns.GetCryptoKeys(domain.FullDomain)
	if err != nil {
		return status
	}
	status["keys"] = dnssecKeyView(cryptoKeys)

	if domain.RootDomain == nil {
		return status
	}
	expected := map[string]bool{}
	for _, k := range cryptoKeys {
		if k.Active && k.Published {
			for _, ds := range k.DS {
				expected[strings.ToLower(strings.Join(strings.Fields(ds), " "))] = true
			}
		}
	}
	published, err := h.pdns.GetRRset(domain.RootDomain.Domain, domain.FullDomain, "DS")
	if err != nil || len(published) == 0 || len(expected) == 0 {
		return status
	}
	dsPublished := false
	for _, r := range published {
		if !r.Disabled && expected[strings.ToLower(strings.Join(strings.Fields(r.Content), " "))] {
			dsPublished = true
			break
		}
	}
	status["ds_published"] = dsPublished
	status["chain_valid"] = dsPublished && status["parent_signed"] == true
	return status
}

// loadOwnedDomain 加载域名并校验所有权；失败时已写入响应
func (h *DomainHandler) loadOwnedDomain(c *gin.Context) (*models.Domain, bool) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return nil, false
	}

	var domain models.Domain
	if err := h.db.Preload("RootDomain").First(&domain, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return nil, false
	}

	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return nil, false
	}
	return &domain, true
}

// GetDomainDNSSEC 获取域名 DNSSEC 状态和密钥信息
// @Summary 获取域名 DNSSEC 状态
// @Tags Domain
// @Produce json
// @Param id path int true "域名 ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/domains/{id}/dnssec [get]
// @Security Bearer
func (h *DomainHandler) GetDomainDNSSEC(c *gin.Context) {
	domain, ok := h.loadOwnedDomain(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, h.domainDNSSECStatus(domain))
}

// EnableDomainDNSSEC 为域名启用 DNSSEC
// @Summary 启用域名 DNSSEC
// @Tags Domain
// @Produce json
// @Param id path int true "域名 ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/domains/{id}/dnssec/enable [post]
// @Security Bearer
func (h *DomainHandler) EnableDomainDNSSEC(c *gin.Context) {
	domain, ok := h.loadOwnedDomain(c)
	if !ok {
		return
	}
	if domain.RootDomain == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parent zone not found"})
		return
	}
	if !domain.UseDefaultNameservers {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This domain uses custom nameservers: sign the zone at your DNS provider, then submit its DS records via POST /api/domains/:id/dnssec/publish-ds"})
		return
	}
	if domain.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DNSSEC can only be enabled for active domains"})
		return
	}

	// A child zone is not reachable (and cannot form a DNSSEC chain) until its
	// NS RRset is also published at the signed parent delegation point.
	nameservers := ensureCanonicalNS([]string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2})
	if err := h.pdns.EnsureDelegatedZone(domain.FullDomain, domain.RootDomain.Domain, nameservers); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare delegated DNS zone: " + err.Error()})
		return
	}

	if err := h.pdns.EnableDNSSEC(domain.FullDomain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable DNSSEC: " + err.Error()})
		return
	}

	// The parent zone is hosted here too, so the DS can be published right away.
	// Without it the child stays "insecure" from a validator's point of view.
	if err := h.pdns.PublishDSToParentZone(domain.FullDomain, domain.RootDomain.Domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DNSSEC keys were created but publishing DS records to the parent zone failed: " + err.Error()})
		return
	}

	status := h.domainDNSSECStatus(domain)
	status["message"] = "DNSSEC enabled successfully"
	if status["parent_signed"] != true {
		status["warning"] = fmt.Sprintf("Parent zone %s is not DNSSEC signed yet; the chain of trust will be incomplete until it is", domain.RootDomain.Domain)
	}
	c.JSON(http.StatusOK, status)
}

// DisableDomainDNSSEC 为域名禁用 DNSSEC
// @Summary 禁用域名 DNSSEC
// @Tags Domain
// @Produce json
// @Param id path int true "域名 ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/domains/{id}/dnssec/disable [post]
// @Security Bearer
func (h *DomainHandler) DisableDomainDNSSEC(c *gin.Context) {
	domain, ok := h.loadOwnedDomain(c)
	if !ok {
		return
	}

	// Break the chain at the parent before removing the child's signing key.
	if domain.RootDomain != nil {
		if err := h.pdns.UnpublishDSFromParentZone(domain.FullDomain, domain.RootDomain.Domain); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to remove parent DS records: " + err.Error()})
			return
		}
	}

	// A missing child zone (e.g. domain moved to custom nameservers) means
	// there is nothing left to unsign.
	if err := h.pdns.DisableDNSSEC(domain.FullDomain); err != nil && !powerdns.IsNotFound(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable DNSSEC: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":      "DNSSEC disabled successfully",
		"enabled":      false,
		"keys":         []interface{}{},
		"ds_published": false,
		"chain_valid":  false,
	})
}

// PublishDomainDSRecords 将子域名的 DS 记录（重新）发布到父 zone。
// 默认 NS：DS 取自本地签名的 child zone，无需请求体。
// 自定义 NS：请求体 {"ds_records": ["<key tag> <algorithm> <digest type> <digest>", ...]}
// 由域名所有者提供（来自其 DNS 服务商），整体替换父 zone 中的 DS。
// @Summary 发布 DS 记录到父 zone
// @Tags Domain
// @Accept json
// @Produce json
// @Param id path int true "域名 ID"
// @Success 200 {object} map[string]interface{}
// @Router /api/domains/{id}/dnssec/publish-ds [post]
// @Security Bearer
func (h *DomainHandler) PublishDomainDSRecords(c *gin.Context) {
	domain, ok := h.loadOwnedDomain(c)
	if !ok {
		return
	}

	if domain.RootDomain == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Parent zone not found"})
		return
	}
	if !domain.UseDefaultNameservers {
		h.publishCustomDSRecords(c, domain)
		return
	}

	defaultNS := ensureCanonicalNS([]string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2})
	if err := h.pdns.EnsureDelegatedZone(domain.FullDomain, domain.RootDomain.Domain, defaultNS); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare delegated DNS zone: " + err.Error()})
		return
	}

	if err := h.pdns.PublishDSToParentZone(domain.FullDomain, domain.RootDomain.Domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to publish DS records: " + err.Error()})
		return
	}

	status := h.domainDNSSECStatus(domain)
	status["message"] = fmt.Sprintf("DS records published to %s successfully", domain.RootDomain.Domain)
	c.JSON(http.StatusOK, status)
}

// publishCustomDSRecords 发布自定义 NS 域名所有者提供的 DS 记录。
// 子 zone 在第三方签名，这里只能在父 zone 的委派点写入 DS；
// 写入错误的 DS 会使域名在验证型解析器上 SERVFAIL，这一后果由所有者承担并可随时撤销。
func (h *DomainHandler) publishCustomDSRecords(c *gin.Context, domain *models.Domain) {
	if domain.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "DS records can only be published for active domains"})
		return
	}

	var req struct {
		DSRecords []string `json:"ds_records"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request body must be {\"ds_records\": [\"<key tag> <algorithm> <digest type> <digest>\"]}"})
		return
	}
	dsRecords, err := normalizeDSRecords(domain.FullDomain, req.DSRecords)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The DS only means something next to the NS delegation; re-assert it so a
	// delegation lost earlier does not leave the DS orphaned.
	var nameservers []string
	_ = json.Unmarshal([]byte(domain.Nameservers), &nameservers)
	normalizedNS, err := normalizeNameservers(nameservers)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "The domain's custom nameservers are invalid: " + err.Error()})
		return
	}
	if err := h.pdns.SetDelegation(domain.RootDomain.Domain, domain.FullDomain, ensureCanonicalNS(normalizedNS)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to publish the NS delegation: " + err.Error()})
		return
	}
	if err := h.pdns.SetParentDS(domain.RootDomain.Domain, domain.FullDomain, dsRecords); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to publish DS records: " + err.Error()})
		return
	}

	status := h.domainDNSSECStatus(domain)
	status["message"] = fmt.Sprintf("DS records published to %s successfully", domain.RootDomain.Domain)
	if status["parent_signed"] != true {
		status["warning"] = fmt.Sprintf("Parent zone %s is not DNSSEC signed yet; the chain of trust will be incomplete until it is", domain.RootDomain.Domain)
	}
	c.JSON(http.StatusOK, status)
}

// DeleteDomain 删除域名
func (h *DomainHandler) DeleteDomain(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("id")

	_, err := h.deleteDomainExclusive(domainID, func(domain *models.Domain) error {
		if domain.UserID != userID {
			return errDomainAccessDenied
		}
		return nil
	}, true)
	if err != nil {
		writeDomainDeleteError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Domain deleted successfully"})
}

var (
	errDomainAccessDenied       = errors.New("access denied")
	errDomainDeletionInProgress = errors.New("domain deletion already in progress")
	errDomainAlreadyDeleted     = errors.New("domain already deleted")
)

const postgresLockNotAvailableError = "55P03"

// deleteDomainExclusive holds a row lock on the domain from before the external
// cleanup until the soft delete commits. Without it, a slow cleanup (PowerDNS
// can take 10s+ to fail) lets duplicate delete requests pile up, and one that
// finishes after the domain was re-registered (restoring the same soft-deleted
// row) deletes the new registration and its DNS data.
func (h *DomainHandler) deleteDomainExclusive(domainID interface{}, authorize func(*models.Domain) error, terminateHosting bool) (*models.Domain, error) {
	var domain models.Domain
	err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "NOWAIT"}).
			First(&domain, domainID).Error; err != nil {
			return err
		}
		if authorize != nil {
			if err := authorize(&domain); err != nil {
				return err
			}
		}
		if domain.RootDomainID > 0 {
			var rootDomain models.RootDomain
			if err := tx.First(&rootDomain, domain.RootDomainID).Error; err == nil {
				domain.RootDomain = &rootDomain
			}
		}

		if terminateHosting && h.cpHandler != nil {
			h.cpHandler.TerminateAccountByDomain(domain.ID)
		}

		if err := h.deleteAllDNSRecordsForDomain(tx, &domain); err != nil {
			fmt.Printf("Warning: Failed to delete DNS records for domain %s: %v\n", domain.FullDomain, err)
			// 继续删除域名，即使 DNS 清理失败
		}

		result := tx.Delete(&domain)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return errDomainAlreadyDeleted
		}
		return nil
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == postgresLockNotAvailableError {
			return nil, errDomainDeletionInProgress
		}
		return nil, err
	}
	return &domain, nil
}

func writeDomainDeleteError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound), errors.Is(err, errDomainAlreadyDeleted):
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
	case errors.Is(err, errDomainAccessDenied):
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
	case errors.Is(err, errDomainDeletionInProgress):
		c.JSON(http.StatusConflict, gin.H{"error": "Domain deletion is already in progress"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete domain"})
	}
}

// ModifyNameservers 修改域名 Nameservers
func (h *DomainHandler) ModifyNameservers(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("id")

	var domain models.Domain
	if err := h.db.Preload("RootDomain").First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	// 验证所有权
	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.Status == "abuse" {
		c.JSON(http.StatusForbidden, gin.H{"error": "This domain has been flagged for abuse. All operations are disabled."})
		return
	}

	var req struct {
		Nameservers []string `json:"nameservers" binding:"required,min=1"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证并规范化 nameservers（去空白、小写、去重、校验主机名）
	normalized, err := normalizeNameservers(req.Nameservers)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.Nameservers = normalized

	// 更新域名的 nameservers（存储为 JSON）
	nameserversJSON, err := json.Marshal(req.Nameservers)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode nameservers"})
		return
	}

	// 判断是否为默认 NS
	defaultNS := []string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2}
	isDefault := sameNameservers(req.Nameservers, defaultNS)

	// A DS submitted for the previous custom nameservers describes keys the
	// new ones do not hold; it must go before the delegation changes.
	var previousNS []string
	_ = json.Unmarshal([]byte(domain.Nameservers), &previousNS)
	dropCustomDS := !domain.UseDefaultNameservers && !isDefault && !sameNameservers(previousNS, req.Nameservers)

	if err := h.db.Model(&domain).Updates(map[string]interface{}{
		"nameservers":             string(nameserversJSON),
		"use_default_nameservers": isDefault,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update nameservers"})
		return
	}

	// 在 PowerDNS 中更新 NS 记录
	if domain.RootDomain != nil {
		go func() {
			if dropCustomDS {
				if err := h.pdns.UnpublishDSFromParentZone(domain.FullDomain, domain.RootDomain.Domain); err != nil {
					fmt.Printf("Warning: Failed to remove custom-NS DS records for %s: %v\n", domain.FullDomain, err)
					return
				}
			}
			h.updateDomainNSRecordsInPowerDNS(&domain, req.Nameservers, isDefault)
		}()
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Nameservers updated successfully",
		"nameservers": req.Nameservers,
	})
}

// RenewDomain 续费域名
func (h *DomainHandler) RenewDomain(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("id")

	var domain models.Domain
	if err := h.db.Preload("RootDomain").First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	// 验证所有权
	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.Status == "abuse" {
		c.JSON(http.StatusForbidden, gin.H{"error": "This domain has been flagged for abuse. All operations are disabled."})
		return
	}

	var req struct {
		Years      int     `json:"years"`
		IsLifetime bool    `json:"is_lifetime"`
		CouponCode *string `json:"coupon_code"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证参数
	if !req.IsLifetime && (req.Years < 1 || req.Years > 10) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Years must be between 1 and 10"})
		return
	}

	// 如果是付费域名，需要创建续费订单
	if !domain.RootDomain.IsFree {
		// 计算价格
		var basePrice float64
		if req.IsLifetime {
			if domain.RootDomain.LifetimePrice == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Lifetime pricing not available"})
				return
			}
			basePrice = *domain.RootDomain.LifetimePrice
		} else {
			if domain.RootDomain.PricePerYear == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Pricing not configured"})
				return
			}
			basePrice = *domain.RootDomain.PricePerYear * float64(req.Years)
		}

		// 应用优惠券
		var discountAmount float64
		var couponID *uint
		var couponCode *string

		if req.CouponCode != nil && *req.CouponCode != "" {
			var coupon models.Coupon
			if err := h.db.Where("UPPER(code) = UPPER(?)", *req.CouponCode).First(&coupon).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "Coupon not found"})
				return
			}

			// 验证优惠券
			if err := h.validateCouponForOrder(&coupon, userID); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			// 应用折扣
			if coupon.DiscountType == "percentage" && coupon.DiscountValue != nil {
				discountAmount = basePrice * (*coupon.DiscountValue / 100.0)
			} else if coupon.DiscountType == "fixed" && coupon.DiscountValue != nil {
				discountAmount = math.Min(*coupon.DiscountValue, basePrice)
			} else if coupon.DiscountType == "quota_increase" {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "This coupon type cannot be used for renewals",
				})
				return
			}

			couponID = &coupon.ID
			couponCode = &coupon.Code
		}

		finalPrice := math.Max(0, basePrice-discountAmount)

		// 生成订单号
		orderNumber := h.generateOrderNumber()

		// 设置年数：如果是lifetime，使用100年满足数据库约束
		years := req.Years
		if req.IsLifetime {
			years = 100
		}

		// 创建续费订单（15分钟后过期）
		order := &models.Order{
			OrderNumber:    orderNumber,
			UserID:         userID,
			RootDomainID:   domain.RootDomainID,
			Subdomain:      domain.Subdomain,
			FullDomain:     domain.FullDomain,
			DomainID:       &domain.ID,
			Years:          years,
			IsLifetime:     req.IsLifetime,
			BasePrice:      basePrice,
			DiscountAmount: discountAmount,
			FinalPrice:     finalPrice,
			Status:         "pending",
			CouponID:       couponID,
			CouponCode:     couponCode,
			ExpiresAt:      timeutil.Now().Add(15 * time.Minute),
		}

		if err := h.db.Create(order).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create order"})
			return
		}

		// 如果最终价格为0或接近0（处理浮点精度问题），直接完成续费
		if finalPrice < 0.01 {
			now := timeutil.Now()
			order.Status = "paid"
			order.PaidAt = &now
			if err := h.db.Save(order).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update order status"})
				return
			}

			// 更新域名过期时间
			maxExpiry := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
			var newExpiry time.Time
			if req.IsLifetime {
				// Lifetime: 设置为100年后
				newExpiry = domain.ExpiresAt.AddDate(100, 0, 0)
			} else {
				newExpiry = domain.ExpiresAt.AddDate(req.Years, 0, 0)
			}
			if newExpiry.After(maxExpiry) {
				newExpiry = maxExpiry
			}

			if err := h.db.Model(&domain).Update("expires_at", newExpiry).Error; err != nil {
				fmt.Printf("Failed to update domain expires_at: %v\n", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to renew domain", "details": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message":          "Domain renewed successfully",
				"requires_payment": false,
				"order_id":         order.ID,
				"order_number":     order.OrderNumber,
				"base_price":       basePrice,
				"discount_amount":  discountAmount,
				"final_price":      finalPrice,
				"coupon_applied":   couponID != nil,
				"years":            years,
				"new_expiry":       newExpiry,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message":          "Renewal order created successfully",
			"requires_payment": finalPrice >= 0.01,
			"order_id":         order.ID,
			"order_number":     order.OrderNumber,
			"base_price":       basePrice,
			"discount_amount":  discountAmount,
			"final_price":      finalPrice,
			"coupon_applied":   couponID != nil,
			"years":            years,
		})
		return
	}

	// 免费域名直接续费
	maxExpiry := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	newExpiry := domain.ExpiresAt.AddDate(req.Years, 0, 0)
	if newExpiry.After(maxExpiry) {
		newExpiry = maxExpiry
	}
	if err := h.db.Model(&domain).Update("expires_at", newExpiry).Error; err != nil {
		fmt.Printf("Failed to update free domain expires_at: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to renew domain", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":    "Domain renewed successfully",
		"new_expiry": newExpiry,
		"years":      req.Years,
	})
}

// validateCouponForOrder 验证订单优惠券
func (h *DomainHandler) validateCouponForOrder(coupon *models.Coupon, userID uint) error {
	now := timeutil.Now()

	// 检查是否激活
	if !coupon.IsActive {
		return fmt.Errorf("coupon is not active")
	}

	// 检查有效期
	if now.Before(coupon.ValidFrom) {
		return fmt.Errorf("coupon not yet valid")
	}
	if coupon.ValidUntil != nil && now.After(*coupon.ValidUntil) {
		return fmt.Errorf("coupon has expired")
	}

	// 检查使用次数
	if coupon.MaxUses > 0 && coupon.UsedCount >= coupon.MaxUses {
		return fmt.Errorf("coupon usage limit reached")
	}

	// 如果优惠券不可重复使用，检查用户是否已使用
	if !coupon.IsReusable {
		var usage models.CouponUsage
		if err := h.db.Where("coupon_id = ? AND user_id = ?", coupon.ID, userID).
			First(&usage).Error; err == nil {
			return fmt.Errorf("you have already used this coupon")
		}
	}

	return nil
}

// generateOrderNumber 生成订单号
func (h *DomainHandler) generateOrderNumber() string {
	// 格式: ORD + 时间戳 + 随机字符
	timestamp := timeutil.Now().Unix()
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomStr := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("ORD%d%s", timestamp, randomStr[:8])
}

// TransferDomain 转移域名（站内转移）
func (h *DomainHandler) TransferDomain(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("id")

	var domain models.Domain
	if err := h.db.First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	// 验证所有权
	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.Status == "abuse" {
		c.JSON(http.StatusForbidden, gin.H{"error": "This domain has been flagged for abuse. All operations are disabled."})
		return
	}

	var req struct {
		Target string `json:"target" binding:"required"` // Email or username
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查找目标用户（通过 email 或 username）
	var targetUser models.User
	if err := h.db.Where("email = ? OR username = ?", req.Target, req.Target).First(&targetUser).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Target user not found"})
		return
	}

	// 不能转移给自己
	if targetUser.ID == userID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot transfer domain to yourself"})
		return
	}

	// 执行转移
	if err := h.db.Model(&domain).Update("user_id", targetUser.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to transfer domain"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Domain transferred successfully",
		"new_owner": targetUser.Email,
		"domain":    domain.FullDomain,
	})
}

// ListAllDomains 管理员：获取所有域名列表（所有用户的域名）
func (h *DomainHandler) ListAllDomains(c *gin.Context) {
	search := c.Query("search")
	status := c.Query("status") // 按状态筛选
	email := c.Query("email")   // 按邮箱精确筛选
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

	// 注意：管理员查看所有域名，不限制user_id
	query := h.db.Model(&models.Domain{})

	// 状态筛选
	if status != "" && (status == "active" || status == "expired" || status == "suspended") {
		query = query.Where("status = ?", status)
	}

	// 邮箱精确筛选
	if email != "" {
		query = query.Joins("LEFT JOIN users ON users.id = domains.user_id").
			Where("users.email = ?", email)
	}

	// 搜索功能：支持按域名、子域名、用户名、邮箱搜索
	if search != "" {
		query = query.Joins("LEFT JOIN users ON users.id = domains.user_id").
			Where("domains.full_domain LIKE ? OR domains.subdomain LIKE ? OR users.username LIKE ? OR users.email LIKE ?",
				"%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// 计算总数
	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count domains"})
		return
	}

	// 分页查询（重新构建query以包含Preload）
	var domains []models.Domain

	domainQuery := h.db.Preload("RootDomain").Preload("User")

	// 状态筛选
	if status != "" && (status == "active" || status == "expired" || status == "suspended" || status == "abuse") {
		domainQuery = domainQuery.Where("status = ?", status)
	}

	// 邮箱精确筛选
	if email != "" {
		domainQuery = domainQuery.Joins("LEFT JOIN users ON users.id = domains.user_id").
			Where("users.email = ?", email)
	}

	if search != "" {
		domainQuery = domainQuery.Joins("LEFT JOIN users ON users.id = domains.user_id").
			Where("domains.full_domain LIKE ? OR domains.subdomain LIKE ? OR users.username LIKE ? OR users.email LIKE ?",
				"%"+search+"%", "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}

	// 如果指定了 email，不分页，返回所有匹配结果
	if email != "" {
		if err := domainQuery.Order("domains.created_at DESC").Find(&domains).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch domains"})
			return
		}
	} else {
		// 没有指定 email，正常分页
		offset := (page - 1) * pageSize
		if err := domainQuery.Order("domains.created_at DESC").Offset(offset).Limit(pageSize).Find(&domains).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch domains"})
			return
		}
	}

	responses := make([]*models.DomainResponse, len(domains))
	for i, domain := range domains {
		responses[i] = domain.ToResponse()
	}

	// 构建响应
	response := gin.H{
		"domains": responses,
	}

	// 只有没有指定 email 时才返回分页信息
	if email == "" {
		totalPages := int(total) / pageSize
		if int(total)%pageSize != 0 {
			totalPages++
		}
		response["pagination"] = gin.H{
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"total_pages": totalPages,
		}
	} else {
		// 指定 email 时，只返回总数
		response["total"] = total
	}

	c.JSON(http.StatusOK, response)
}

// GetDomainStatusStats 管理员：获取域名状态统计
func (h *DomainHandler) GetDomainStatusStats(c *gin.Context) {
	type StatusCount struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}

	var stats []StatusCount
	if err := h.db.Model(&models.Domain{}).
		Select("status, COUNT(*) as count").
		Group("status").
		Find(&stats).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get status stats"})
		return
	}

	// 构建统计结果，确保所有状态都有值
	statusMap := map[string]int64{
		"active":    0,
		"expired":   0,
		"suspended": 0,
		"abuse":     0,
	}

	for _, stat := range stats {
		statusMap[stat.Status] = stat.Count
	}

	// 计算总数
	total := int64(0)
	for _, count := range statusMap {
		total += count
	}

	c.JSON(http.StatusOK, gin.H{
		"total":     total,
		"active":    statusMap["active"],
		"expired":   statusMap["expired"],
		"suspended": statusMap["suspended"],
		"abuse":     statusMap["abuse"],
	})
}

// userLevelOrder 返回用户等级对应的数值（数值越大等级越高）
func userLevelOrder(level string) int {
	switch level {
	case "basic":
		return 1
	case "member":
		return 2
	case "regular":
		return 3
	case "leader":
		return 4
	default: // normal
		return 0
	}
}

// isValidSubdomain 验证子域名格式
func isValidSubdomain(subdomain string) bool {
	// 长度检查
	if len(subdomain) < 3 || len(subdomain) > 63 {
		return false
	}

	// 格式检查：字母、数字、连字符，不能以连字符开头或结尾
	pattern := `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
	matched, _ := regexp.MatchString(pattern, subdomain)
	return matched
}

// defaultBlacklist is the fallback when no DB setting is found
var defaultBlacklist = []string{
	"admin", "root", "api", "www", "mail", "smtp", "ftp", "ssh", "dns",
	"test", "demo", "dev", "stage", "prod", "blog", "forum", "shop",
	"status", "support", "help", "docs", "cdn", "static", "assets",
}

// isBlacklisted 检查子域名是否在黑名单中（黑名单从 system_settings 读取）
func isBlacklisted(db *gorm.DB, subdomain string) bool {
	raw := models.GetSettingValue(db, "subdomain_blacklist", "")

	var list []string
	if raw == "" {
		list = defaultBlacklist
	} else {
		for _, entry := range strings.Split(raw, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				list = append(list, entry)
			}
		}
	}

	for _, word := range list {
		if subdomain == word {
			return true
		}
	}
	return false
}

// Admin Root Domain Management

// ListAllRootDomains 管理员：获取所有根域名列表
func (h *DomainHandler) ListAllRootDomains(c *gin.Context) {
	var rootDomains []models.RootDomain
	if err := h.db.Order("priority DESC, id ASC").Find(&rootDomains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch root domains"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"root_domains": rootDomains})
}

// CreateRootDomain 管理员：创建根域名
func (h *DomainHandler) CreateRootDomain(c *gin.Context) {
	var req struct {
		Domain                string   `json:"domain" binding:"required"`
		Description           *string  `json:"description"`
		Priority              int      `json:"priority"`
		IsActive              bool     `json:"is_active"`
		IsHot                 bool     `json:"is_hot"`
		IsNew                 bool     `json:"is_new"`
		IsFree                bool     `json:"is_free"`
		MinUserLevel          string   `json:"min_user_level"`
		PricePerYear          *float64 `json:"price_per_year"`
		LifetimePrice         *float64 `json:"lifetime_price"`
		UseDefaultNameservers bool     `json:"use_default_nameservers"`
		Nameservers           []string `json:"nameservers"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查域名是否已存在
	var existing models.RootDomain
	if err := h.db.Where("domain = ?", req.Domain).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Root domain already exists"})
		return
	}

	// 设置 nameservers
	var nameserversJSON string
	if req.UseDefaultNameservers {
		// 使用默认 NS
		defaultNS := []string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2}
		nsBytes, err := json.Marshal(defaultNS)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode default nameservers"})
			return
		}
		nameserversJSON = string(nsBytes)
	} else {
		// 使用自定义 NS
		if len(req.Nameservers) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Nameservers required when not using default"})
			return
		}
		normalized, err := normalizeNameservers(req.Nameservers)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		nsBytes, err := json.Marshal(normalized)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode nameservers"})
			return
		}
		nameserversJSON = string(nsBytes)
	}

	minLevel := req.MinUserLevel
	if minLevel == "" {
		minLevel = "normal"
	}

	rootDomain := &models.RootDomain{
		Domain:                req.Domain,
		Description:           req.Description,
		Priority:              req.Priority,
		IsActive:              req.IsActive,
		IsHot:                 req.IsHot,
		IsNew:                 req.IsNew,
		IsFree:                req.IsFree,
		MinUserLevel:          minLevel,
		PricePerYear:          req.PricePerYear,
		LifetimePrice:         req.LifetimePrice,
		UseDefaultNameservers: req.UseDefaultNameservers,
		Nameservers:           nameserversJSON,
	}

	if err := h.db.Create(rootDomain).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create root domain"})
		return
	}

	// 在 PowerDNS 中创建 Zone
	var nameservers []string
	if err := json.Unmarshal([]byte(nameserversJSON), &nameservers); err == nil {
		if err := h.pdns.CreateZone(req.Domain, ensureCanonicalNS(nameservers)); err != nil {
			fmt.Printf("Warning: Failed to create PowerDNS zone for %s: %v\n", req.Domain, err)
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":     "Root domain created successfully",
		"root_domain": rootDomain,
	})
}

// UpdateRootDomain 管理员：更新根域名
func (h *DomainHandler) UpdateRootDomain(c *gin.Context) {
	id := c.Param("id")

	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}

	var req struct {
		Description           *string  `json:"description"`
		Priority              *int     `json:"priority"`
		IsActive              *bool    `json:"is_active"`
		IsHot                 *bool    `json:"is_hot"`
		IsNew                 *bool    `json:"is_new"`
		IsFree                *bool    `json:"is_free"`
		MinUserLevel          *string  `json:"min_user_level"`
		PricePerYear          *float64 `json:"price_per_year"`
		LifetimePrice         *float64 `json:"lifetime_price"`
		UseDefaultNameservers *bool    `json:"use_default_nameservers"`
		Nameservers           []string `json:"nameservers"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新字段
	updates := make(map[string]interface{})
	selectFields := []string{}

	if req.Description != nil {
		updates["description"] = *req.Description
		selectFields = append(selectFields, "description")
	}
	if req.Priority != nil {
		updates["priority"] = *req.Priority
		selectFields = append(selectFields, "priority")
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
		selectFields = append(selectFields, "is_active")
	}
	if req.IsHot != nil {
		updates["is_hot"] = *req.IsHot
		selectFields = append(selectFields, "is_hot")
	}
	if req.IsNew != nil {
		updates["is_new"] = *req.IsNew
		selectFields = append(selectFields, "is_new")
	}
	if req.IsFree != nil {
		updates["is_free"] = *req.IsFree
		selectFields = append(selectFields, "is_free")
	}
	if req.PricePerYear != nil {
		updates["price_per_year"] = *req.PricePerYear
		selectFields = append(selectFields, "price_per_year")
	}
	if req.LifetimePrice != nil {
		updates["lifetime_price"] = *req.LifetimePrice
		selectFields = append(selectFields, "lifetime_price")
	}
	if req.MinUserLevel != nil {
		updates["min_user_level"] = *req.MinUserLevel
		selectFields = append(selectFields, "min_user_level")
	}
	if req.UseDefaultNameservers != nil {
		updates["use_default_nameservers"] = *req.UseDefaultNameservers
		selectFields = append(selectFields, "use_default_nameservers")

		// 如果切换到使用默认 NS，更新 nameservers
		if *req.UseDefaultNameservers {
			defaultNS := []string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2}
			nsBytes, err := json.Marshal(defaultNS)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode default nameservers"})
				return
			}
			updates["nameservers"] = string(nsBytes)
			selectFields = append(selectFields, "nameservers")
		} else {
			// 如果切换到自定义 NS，需要提供 nameservers
			if len(req.Nameservers) > 0 {
				normalized, err := normalizeNameservers(req.Nameservers)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}
				nsBytes, err := json.Marshal(normalized)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode nameservers"})
					return
				}
				updates["nameservers"] = string(nsBytes)
				selectFields = append(selectFields, "nameservers")
			}
		}
	}

	if err := h.db.Model(&rootDomain).Select(selectFields).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update root domain"})
		return
	}

	// Reload the root domain to get fresh data
	if err := h.db.First(&rootDomain, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reload root domain"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Root domain updated successfully",
		"root_domain": rootDomain,
	})
}

// DeleteRootDomain 管理员：删除根域名
func (h *DomainHandler) DeleteRootDomain(c *gin.Context) {
	id := c.Param("id")

	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}

	// 检查是否有子域名在使用
	var count int64
	h.db.Model(&models.Domain{}).Where("root_domain_id = ?", id).Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Cannot delete: %d domains are using this root domain", count)})
		return
	}

	if err := h.db.Delete(&rootDomain).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete root domain"})
		return
	}

	// 从 PowerDNS 删除 Zone
	if err := h.pdns.DeleteZone(rootDomain.Domain); err != nil {
		fmt.Printf("Warning: Failed to delete PowerDNS zone for %s: %v\n", rootDomain.Domain, err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Root domain deleted successfully"})
}

// rootDomainDNSSECStatus 汇总根域名 zone 的 DNSSEC 状态。
// 根域名的 DS 需要由管理员手动配置到上级注册商，因此这里返回 DS 内容供复制。
func (h *DomainHandler) rootDomainDNSSECStatus(rootDomain *models.RootDomain) gin.H {
	status := gin.H{
		"domain":      rootDomain.Domain,
		"zone_exists": false,
		"enabled":     false,
		"keys":        []interface{}{},
		"ds_records":  []string{},
	}
	zone, err := h.pdns.GetZoneInfo(rootDomain.Domain)
	if err != nil {
		return status
	}
	status["zone_exists"] = true
	if !zone.DNSsec {
		return status
	}
	status["enabled"] = true

	cryptoKeys, err := h.pdns.GetCryptoKeys(rootDomain.Domain)
	if err != nil {
		return status
	}
	status["keys"] = dnssecKeyView(cryptoKeys)
	ds := []string{}
	for _, k := range cryptoKeys {
		if k.Active && k.Published {
			ds = append(ds, k.DS...)
		}
	}
	status["ds_records"] = ds
	return status
}

// GetRootDomainDNSSEC 管理员：获取根域名 DNSSEC 状态与 DS 记录
func (h *DomainHandler) GetRootDomainDNSSEC(c *gin.Context) {
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}
	status := h.rootDomainDNSSECStatus(&rootDomain)
	delegationRepairMu.Lock()
	if st := delegationRepairStatus[rootDomain.ID]; st != nil {
		copyStatus := *st
		copyStatus.Errors = append([]string{}, st.Errors...)
		status["repair"] = copyStatus
	}
	if st := orphanCleanupStatus[rootDomain.ID]; st != nil {
		copyStatus := *st
		copyStatus.Errors = append([]string{}, st.Errors...)
		status["orphan_cleanup"] = copyStatus
	}
	delegationRepairMu.Unlock()
	c.JSON(http.StatusOK, status)
}

// EnableRootDomainDNSSEC 管理员：为根域名 zone 启用 DNSSEC。
// 子域名的 DS 只有在根域名自身已签名、且根域名的 DS 已在注册商处配置时才能形成完整信任链。
func (h *DomainHandler) EnableRootDomainDNSSEC(c *gin.Context) {
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}
	if !rootDomain.UseDefaultNameservers {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Root domain is served by external nameservers; DNSSEC must be configured there"})
		return
	}

	var nameservers []string
	if rootDomain.Nameservers != "" {
		_ = json.Unmarshal([]byte(rootDomain.Nameservers), &nameservers)
	}
	if len(nameservers) == 0 {
		nameservers = []string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2}
	}
	if err := h.pdns.EnsureZone(rootDomain.Domain, ensureCanonicalNS(nameservers)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare DNS zone: " + err.Error()})
		return
	}

	if err := h.pdns.EnableDNSSEC(rootDomain.Domain); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable DNSSEC: " + err.Error()})
		return
	}

	status := h.rootDomainDNSSECStatus(&rootDomain)
	status["message"] = fmt.Sprintf("DNSSEC enabled for %s. Publish the DS records at your registrar to complete the chain of trust.", rootDomain.Domain)
	c.JSON(http.StatusOK, status)
}

// DisableRootDomainDNSSEC 管理员：为根域名 zone 禁用 DNSSEC。
// 调用前必须先在注册商处删除 DS 记录，否则整个根域名及其所有子域名都会解析失败。
func (h *DomainHandler) DisableRootDomainDNSSEC(c *gin.Context) {
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}

	if err := h.pdns.DisableDNSSEC(rootDomain.Domain); err != nil && !powerdns.IsNotFound(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable DNSSEC: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     fmt.Sprintf("DNSSEC disabled for %s", rootDomain.Domain),
		"domain":      rootDomain.Domain,
		"zone_exists": true,
		"enabled":     false,
		"keys":        []interface{}{},
		"ds_records":  []string{},
	})
}

// DelegationRepairStatus 记录一次批量委派修复的进度/结果
type DelegationRepairStatus struct {
	Running    bool      `json:"running"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Total      int       `json:"total"`
	Delegated  int       `json:"delegated"`
	WithDS     int       `json:"with_ds"`
	NoZone     int       `json:"no_zone"`
	Suspended  int       `json:"suspended"`
	Errors     []string  `json:"errors"`
}

// OrphanCleanupStatus 记录一次孤儿 zone 清理的进度/结果
type OrphanCleanupStatus struct {
	Running    bool      `json:"running"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Total      int       `json:"total"`
	Deleted    int       `json:"deleted"`
	Errors     []string  `json:"errors"`
}

var orphanCleanupStatus = map[uint]*OrphanCleanupStatus{}

// findOrphanZones 返回 PowerDNS 中位于根域名之下、但数据库里已无对应有效域名的 zone 及根域中的 NS 委派。
func (h *DomainHandler) findOrphanZones(rootDomain *models.RootDomain) ([]string, error) {
	zones, err := h.pdns.ListZones()
	if err != nil {
		return nil, fmt.Errorf("failed to list PowerDNS zones: %w", err)
	}
	var live []string
	if err := h.db.Model(&models.Domain{}).
		Where("root_domain_id = ? AND status <> ?", rootDomain.ID, "deleted").
		Pluck("full_domain", &live).Error; err != nil {
		return nil, fmt.Errorf("failed to load domains: %w", err)
	}
	liveSet := make(map[string]bool, len(live))
	for _, d := range live {
		liveSet[strings.ToLower(d)] = true
	}
	suffix := "." + strings.ToLower(rootDomain.Domain)
	seen := map[string]bool{}
	var orphans []string
	add := func(fqdn string) {
		name := strings.ToLower(strings.TrimSuffix(fqdn, "."))
		if !strings.HasSuffix(name, suffix) || liveSet[name] || seen[name] {
			return
		}
		seen[name] = true
		orphans = append(orphans, name)
	}
	for _, z := range zones {
		add(z.Name)
	}
	// Delegations of domains using external nameservers have no child zone,
	// so they only show up as NS RRsets in the root zone. Left behind, they
	// keep resolving to whoever now controls those nameservers.
	root, err := h.pdns.GetZone(rootDomain.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to load root zone %s: %w", rootDomain.Domain, err)
	}
	for _, rrset := range root.RRsets {
		if rrset.Type == "NS" {
			add(rrset.Name)
		}
	}
	sort.Strings(orphans)
	return orphans, nil
}

// ListOrphanZones 管理员：列出根域名下的孤儿 zone（预览，不做修改）
func (h *DomainHandler) ListOrphanZones(c *gin.Context) {
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}
	orphans, err := h.findOrphanZones(&rootDomain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if orphans == nil {
		orphans = []string{}
	}
	c.JSON(http.StatusOK, gin.H{"root_domain": rootDomain.Domain, "count": len(orphans), "zones": orphans})
}

// CleanupOrphanZones 管理员：删除孤儿 zone 及其在父区中的 NS/DS 委派（异步）。
// 孤儿 zone 仍会被 PowerDNS 应答（已签名的还会因缺少 DS 而 SERVFAIL），
// 但数据库中已没有对应域名，属于历史遗留，应清理为 NXDOMAIN。
func (h *DomainHandler) CleanupOrphanZones(c *gin.Context) {
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}
	orphans, err := h.findOrphanZones(&rootDomain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	delegationRepairMu.Lock()
	if st := orphanCleanupStatus[rootDomain.ID]; st != nil && st.Running {
		delegationRepairMu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "An orphan zone cleanup is already running for this root domain", "orphan_cleanup": st})
		return
	}
	status := &OrphanCleanupStatus{Running: true, StartedAt: time.Now(), Total: len(orphans), Errors: []string{}}
	orphanCleanupStatus[rootDomain.ID] = status
	delegationRepairMu.Unlock()

	go func() {
		addError := func(format string, args ...interface{}) {
			msg := fmt.Sprintf(format, args...)
			fmt.Printf("[orphan-cleanup] %s\n", msg)
			delegationRepairMu.Lock()
			if len(status.Errors) < 50 {
				status.Errors = append(status.Errors, msg)
			}
			delegationRepairMu.Unlock()
		}
		// Parent first: once NS/DS are gone the names fall back to NXDOMAIN
		// even if a zone deletion below fails.
		if err := h.pdns.RemoveDelegations(rootDomain.Domain, orphans); err != nil {
			addError("failed to remove delegations: %v", err)
		}
		for _, zone := range orphans {
			if err := h.pdns.DeleteZone(zone); err != nil && !powerdns.IsNotFound(err) {
				addError("%s: %v", zone, err)
				continue
			}
			delegationRepairMu.Lock()
			status.Deleted++
			delegationRepairMu.Unlock()
		}
		delegationRepairMu.Lock()
		status.Running = false
		status.FinishedAt = time.Now()
		delegationRepairMu.Unlock()
		fmt.Printf("[orphan-cleanup] %s: deleted %d/%d orphan zones\n", rootDomain.Domain, status.Deleted, status.Total)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message":        fmt.Sprintf("Cleanup of %d orphan zones under %s started", len(orphans), rootDomain.Domain),
		"orphan_cleanup": status,
	})
}

var (
	delegationRepairMu     sync.Mutex
	delegationRepairStatus = map[uint]*DelegationRepairStatus{}
)

// RepairRootDomainDelegations 管理员：为根域名下所有子域名重新发布父区委派。
//
// 历史子 zone 只是在 PowerDNS 里独立存在，父区中没有 NS/DS 记录。父区签名后，
// 验证型解析器无法证明这些子域名是"不安全委派"，已签名的子域名会直接 SERVFAIL。
// 此接口一次性补齐：默认 NS 的子 zone 发布 NS（已签名者附带 DS），
// 自定义 NS 的域名发布其 NS。任务异步执行，进度通过 GET /dnssec 查询。
func (h *DomainHandler) RepairRootDomainDelegations(c *gin.Context) {
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}
	if !rootDomain.UseDefaultNameservers {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Root domain is served by external nameservers"})
		return
	}

	var domains []models.Domain
	if err := h.db.Where("root_domain_id = ?", rootDomain.ID).Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load domains"})
		return
	}

	delegationRepairMu.Lock()
	if st := delegationRepairStatus[rootDomain.ID]; st != nil && st.Running {
		delegationRepairMu.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "A delegation repair is already running for this root domain", "repair": st})
		return
	}
	status := &DelegationRepairStatus{Running: true, StartedAt: time.Now(), Total: len(domains), Errors: []string{}}
	delegationRepairStatus[rootDomain.ID] = status
	delegationRepairMu.Unlock()

	go h.runDelegationRepair(rootDomain, domains, status)

	c.JSON(http.StatusAccepted, gin.H{
		"message": fmt.Sprintf("Delegation repair started for %d domains under %s", len(domains), rootDomain.Domain),
		"repair":  status,
	})
}

func (h *DomainHandler) runDelegationRepair(rootDomain models.RootDomain, domains []models.Domain, status *DelegationRepairStatus) {
	addError := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		fmt.Printf("[delegation-repair] %s\n", msg)
		delegationRepairMu.Lock()
		if len(status.Errors) < 50 {
			status.Errors = append(status.Errors, msg)
		}
		delegationRepairMu.Unlock()
	}
	finish := func() {
		delegationRepairMu.Lock()
		status.Running = false
		status.FinishedAt = time.Now()
		delegationRepairMu.Unlock()
	}

	zones, err := h.pdns.ListZones()
	if err != nil {
		addError("failed to list PowerDNS zones: %v", err)
		finish()
		return
	}
	signed := map[string]bool{}
	for _, z := range zones {
		signed[strings.ToLower(strings.TrimSuffix(z.Name, "."))] = z.DNSsec
	}

	// DS records of custom-NS domains were submitted by their owners and exist
	// only in the parent zone; carry them over instead of deleting them.
	parent, err := h.pdns.GetZone(rootDomain.Domain)
	if err != nil {
		addError("failed to read parent zone %s: %v", rootDomain.Domain, err)
		finish()
		return
	}
	parentDS := map[string][]string{}
	for _, rrset := range parent.RRsets {
		if rrset.Type != "DS" {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(rrset.Name, "."))
		for _, r := range rrset.Records {
			parentDS[name] = append(parentDS[name], r.Content)
		}
	}

	defaultNS := ensureCanonicalNS([]string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2})
	var delegations []powerdns.Delegation
	for _, d := range domains {
		name := strings.ToLower(d.FullDomain)
		if !d.UseDefaultNameservers {
			var ns []string
			if d.Nameservers != "" {
				_ = json.Unmarshal([]byte(d.Nameservers), &ns)
			}
			normalized, err := normalizeNameservers(ns)
			if err != nil {
				addError("%s: invalid custom nameservers %v (%v); skipped", d.FullDomain, ns, err)
				continue
			}
			del := powerdns.Delegation{Child: d.FullDomain, Nameservers: ensureCanonicalNS(normalized)}
			// A leftover local zone means the DS may be ours and stale; drop it.
			if _, leftover := signed[name]; !leftover {
				del.DS = parentDS[name]
			}
			delegations = append(delegations, del)
			continue
		}

		isSigned, hasZone := signed[name]
		if !hasZone {
			// No child zone (domain never had records). A delegation to a
			// nonexistent zone would turn NXDOMAIN into REFUSED, so leave it.
			delegationRepairMu.Lock()
			status.NoZone++
			delegationRepairMu.Unlock()
			continue
		}
		del := powerdns.Delegation{Child: d.FullDomain, Nameservers: defaultNS}
		if isSigned {
			ds, err := h.pdns.ActiveDSRecords(d.FullDomain)
			if err != nil {
				addError("%s: failed to read DS: %v", d.FullDomain, err)
			} else {
				del.DS = ds
			}
			if err := h.pdns.EnableAPIRectify(d.FullDomain); err != nil {
				addError("%s: failed to enable api-rectify: %v", d.FullDomain, err)
			}
		}
		delegations = append(delegations, del)
	}

	failed := 0
	if err := h.pdns.SetDelegations(rootDomain.Domain, delegations); err != nil {
		var partial *powerdns.DelegationErrors
		if errors.As(err, &partial) {
			// The rest of the batch was published; only report the bad ones.
			failed = len(partial.Failures)
			for _, f := range partial.Failures {
				addError("%v", f)
			}
		} else {
			addError("failed to publish delegations in %s: %v", rootDomain.Domain, err)
			finish()
			return
		}
	}

	delegationRepairMu.Lock()
	status.Delegated = len(delegations) - failed
	for _, d := range delegations {
		if len(d.DS) > 0 {
			status.WithDS++
		}
	}
	delegationRepairMu.Unlock()

	// Re-apply suspension: newly published delegations would otherwise make
	// suspended domains resolvable again.
	for i := range domains {
		if domains[i].Status != "suspended" {
			continue
		}
		if err := h.pdns.SetDomainSuspended(rootDomain.Domain, domains[i].FullDomain, true); err != nil {
			addError("%s: failed to re-apply suspension: %v", domains[i].FullDomain, err)
			continue
		}
		delegationRepairMu.Lock()
		status.Suspended++
		delegationRepairMu.Unlock()
	}
	fmt.Printf("[delegation-repair] %s: %d delegations published (%d with DS, %d without zone)\n",
		rootDomain.Domain, status.Delegated, status.WithDS, status.NoZone)
	finish()
}

// ListDomainsByRootDomain 管理员：获取某个根域名下的所有域名
func (h *DomainHandler) ListDomainsByRootDomain(c *gin.Context) {
	rootDomainID := c.Param("id")
	search := c.Query("search")

	// 验证根域名存在
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, rootDomainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}

	page := 1
	pageSize := 50
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(c.Query("page_size")); err == nil && ps > 0 && ps <= 200 {
		pageSize = ps
	}

	filtered := func() *gorm.DB {
		q := h.db.Model(&models.Domain{}).Where("root_domain_id = ?", rootDomain.ID)
		if search != "" {
			q = q.Where("subdomain ILIKE ? OR full_domain ILIKE ?",
				"%"+search+"%", "%"+search+"%")
		}
		return q
	}

	var total int64
	if err := filtered().Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count domains"})
		return
	}

	var domains []models.Domain
	if err := filtered().Preload("User").Preload("RootDomain").
		Order("created_at DESC").Order("id DESC").
		Offset((page - 1) * pageSize).Limit(pageSize).
		Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch domains"})
		return
	}

	responses := make([]*models.DomainResponse, len(domains))
	for i, domain := range domains {
		responses[i] = domain.ToResponse()
	}

	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	c.JSON(http.StatusOK, gin.H{
		"domains":     responses,
		"root_domain": rootDomain,
		"pagination": gin.H{
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"total_pages": totalPages,
		},
	})
}

// AdminUpdateDomainStatus 管理员：更新域名状态
func (h *DomainHandler) AdminUpdateDomainStatus(c *gin.Context) {
	domainID := c.Param("id")

	var req struct {
		Status string  `json:"status" binding:"required,oneof=active suspended"`
		Reason *string `json:"reason"` // 挂起原因（当 status 为 suspended 时可选）
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 如果是挂起操作且没有提供原因，返回错误
	if req.Status == "suspended" && (req.Reason == nil || *req.Reason == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Reason is required when suspending a domain"})
		return
	}

	var domain models.Domain
	if err := h.db.Preload("User").Preload("RootDomain").First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	oldStatus := domain.Status
	now := timeutil.Now()

	// 更新域名状态
	updates := map[string]interface{}{
		"status": req.Status,
	}

	if req.Status == "suspended" {
		// 挂起域名：记录时间和原因
		updates["suspended_at"] = now
		updates["suspend_reason"] = *req.Reason

		// 记录到 suspend_history 表
		history := models.SuspendHistory{
			DomainID: domain.ID,
			Reason:   "Manual suspension by admin",
			Details:  *req.Reason,
		}
		h.db.Create(&history)
	} else if req.Status == "active" && oldStatus == "suspended" {
		// 激活域名：清除挂起信息
		updates["suspended_at"] = nil
		updates["suspend_reason"] = nil
		updates["first_failed_at"] = nil // 同时清除失败记录
	}

	if err := h.db.Model(&domain).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update domain status"})
		return
	}

	// 同步 PowerDNS：挂起时停止解析（子 zone 记录 + 父区委派/历史记录），激活时恢复
	if domain.RootDomain != nil {
		suspended := req.Status == "suspended"
		go func() {
			if err := h.pdns.SetDomainSuspended(domain.RootDomain.Domain, domain.FullDomain, suspended); err != nil {
				fmt.Printf("Warning: Failed to %s resolution in PowerDNS for %s: %v\n",
					map[bool]string{true: "suspend", false: "restore"}[suspended], domain.FullDomain, err)
			}
		}()
	}

	// 联动 CyberPanel：同步主机账号状态
	if h.cpHandler != nil {
		go func() {
			if req.Status == "suspended" {
				h.cpHandler.SuspendAccountByDomain(domain.ID)
			} else if req.Status == "active" && oldStatus == "suspended" {
				h.cpHandler.UnsuspendAccountByDomain(domain.ID)
			}
		}()
	}

	// 重新加载域名数据以返回最新信息
	if err := h.db.Preload("User").Preload("RootDomain").First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reload domain"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Domain status updated",
		"domain":  domain.ToResponse(),
	})
}

// deleteAllDNSRecordsForDomain 删除域名的所有 DNS 记录（从数据库和 PowerDNS）
func (h *DomainHandler) deleteAllDNSRecordsForDomain(db *gorm.DB, domain *models.Domain) error {
	// Delegation and zone cleanup must run even when the domain has no user
	// records. Otherwise empty/stale zones and orphaned DS records accumulate.
	if domain.RootDomain != nil {
		if err := h.pdns.RemoveDelegation(domain.RootDomain.Domain, domain.FullDomain); err != nil {
			return fmt.Errorf("failed to remove DNS delegation: %w", err)
		}
		if domain.UseDefaultNameservers {
			if err := h.pdns.DeleteZone(domain.FullDomain); err != nil &&
				!strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "Could not find") {
				return fmt.Errorf("failed to delete child DNS zone: %w", err)
			}
		}
	}

	// 从数据库删除所有 DNS 记录
	if err := db.Where("domain_id = ?", domain.ID).Delete(&models.DNSRecord{}).Error; err != nil {
		return fmt.Errorf("failed to delete DNS records from database: %w", err)
	}

	return nil
}

// AdminDeleteDomain 管理员：删除域名
func (h *DomainHandler) AdminDeleteDomain(c *gin.Context) {
	domainID := c.Param("id")

	domain, err := h.deleteDomainExclusive(domainID, nil, true)
	if err != nil {
		writeDomainDeleteError(c, err)
		return
	}

	// 减少根域名注册计数
	h.db.Model(&models.RootDomain{}).Where("id = ?", domain.RootDomainID).
		UpdateColumn("registration_count", gorm.Expr("GREATEST(registration_count - 1, 0)"))

	c.JSON(http.StatusOK, gin.H{"message": "Domain deleted successfully"})
}

// AdminCreateDomainForUser 管理员为指定用户新增域名（绕过配额和付费限制）
func (h *DomainHandler) AdminCreateDomainForUser(c *gin.Context) {
	var req models.AdminCreateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 默认注册年限为 1 年
	years := req.Years
	if years <= 0 {
		years = 1
	}

	// 验证目标用户存在
	var user models.User
	if err := h.db.First(&user, req.UserID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// 验证根域名存在且启用
	var rootDomain models.RootDomain
	if err := h.db.First(&rootDomain, req.RootDomainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Root domain not found"})
		return
	}

	if !rootDomain.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Root domain is not active"})
		return
	}

	// 验证子域名格式
	if !isValidSubdomain(req.Subdomain) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid subdomain format"})
		return
	}

	fullDomain := fmt.Sprintf("%s.%s", req.Subdomain, rootDomain.Domain)

	// 检查域名是否已存在（非软删除）
	var activeCheck models.Domain
	if err := h.db.Where("full_domain = ?", fullDomain).First(&activeCheck).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Domain already registered"})
		return
	}

	// 检查是否存在软删除记录（唯一约束仍生效，需要先恢复再更新）
	var deletedDomain models.Domain
	hasSoftDeleted := h.db.Unscoped().Where("full_domain = ? AND deleted_at IS NOT NULL", fullDomain).First(&deletedDomain).Error == nil

	// 事务创建域名
	var domain models.Domain
	err := h.db.Transaction(func(tx *gorm.DB) error {
		now := timeutil.Now()
		if hasSoftDeleted {
			// 恢复软删除记录并更新字段
			updates := map[string]interface{}{
				"user_id":                 req.UserID,
				"root_domain_id":          req.RootDomainID,
				"subdomain":               req.Subdomain,
				"status":                  "active",
				"registered_at":           now,
				"expires_at":              now.AddDate(years, 0, 0),
				"auto_renew":              false,
				"nameservers":             rootDomain.Nameservers,
				"use_default_nameservers": rootDomain.UseDefaultNameservers,
				"dns_synced":              false,
				"dns_sync_error":          nil,
				"first_failed_at":         nil,
				"suspended_at":            nil,
				"suspend_reason":          nil,
				"deleted_at":              nil,
			}
			if err := tx.Unscoped().Model(&deletedDomain).Updates(updates).Error; err != nil {
				return err
			}
			domain = deletedDomain
		} else {
			domain = models.Domain{
				UserID:                req.UserID,
				RootDomainID:          req.RootDomainID,
				Subdomain:             req.Subdomain,
				FullDomain:            fullDomain,
				Status:                "active",
				RegisteredAt:          now,
				ExpiresAt:             now.AddDate(years, 0, 0),
				AutoRenew:             false,
				Nameservers:           rootDomain.Nameservers,
				UseDefaultNameservers: rootDomain.UseDefaultNameservers,
				DNSSynced:             false,
			}
			if err := tx.Create(&domain).Error; err != nil {
				return err
			}
		}

		// 更新根域名注册计数
		if err := tx.Model(&rootDomain).
			UpdateColumn("registration_count", gorm.Expr("registration_count + ?", 1)).Error; err != nil {
			return err
		}

		return tx.Preload("RootDomain").First(&domain, domain.ID).Error
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create domain"})
		return
	}

	// 在 PowerDNS 中配置域名 NS 记录
	if domain.RootDomain != nil {
		var nameservers []string
		if err := json.Unmarshal([]byte(domain.Nameservers), &nameservers); err == nil {
			go h.updateDomainNSRecordsInPowerDNS(&domain, nameservers, domain.UseDefaultNameservers)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Domain created successfully",
		"domain":  domain.ToResponse(),
	})
}

// CleanupExpiredDomains 自动清理过期域名
// 删除过期超过指定天数的域名及其 DNS 记录
func (h *DomainHandler) CleanupExpiredDomains(daysAfterExpiry int) {
	if daysAfterExpiry <= 0 {
		daysAfterExpiry = 30 // 默认过期 30 天后删除
	}

	cutoffTime := timeutil.Now().AddDate(0, 0, -daysAfterExpiry)

	fmt.Printf("Starting cleanup of domains expired before %s...\n", cutoffTime.Format("2006-01-02 15:04:05"))

	// 查找过期超过指定天数的域名
	var expiredDomains []models.Domain
	if err := h.db.Preload("RootDomain").
		Where("expires_at < ? AND status != ?", cutoffTime, "suspended").
		Find(&expiredDomains).Error; err != nil {
		fmt.Printf("Error querying expired domains: %v\n", err)
		return
	}

	if len(expiredDomains) == 0 {
		fmt.Println("No expired domains to clean up.")
		return
	}

	fmt.Printf("Found %d expired domains to clean up.\n", len(expiredDomains))

	successCount := 0
	failCount := 0

	for _, domain := range expiredDomains {
		fmt.Printf("Cleaning up domain: %s (expired at %s)\n",
			domain.FullDomain, domain.ExpiresAt.Format("2006-01-02"))

		_, err := h.deleteDomainExclusive(domain.ID, func(locked *models.Domain) error {
			if !locked.ExpiresAt.Before(cutoffTime) || locked.Status == "suspended" {
				return fmt.Errorf("domain no longer eligible for expiry cleanup")
			}
			return nil
		}, false)
		if err != nil {
			fmt.Printf("Error: Failed to delete domain %s: %v\n", domain.FullDomain, err)
			failCount++
			continue
		}

		// 减少根域名注册计数
		if domain.RootDomainID > 0 {
			h.db.Model(&models.RootDomain{}).Where("id = ?", domain.RootDomainID).
				UpdateColumn("registration_count", gorm.Expr("GREATEST(registration_count - 1, 0)"))
		}

		successCount++
	}

	fmt.Printf("Cleanup completed: %d domains deleted, %d failed.\n", successCount, failCount)
}

// updateDomainNSRecordsInPowerDNS 更新域名在 PowerDNS root zone 中的 NS 记录
// 默认和自定义 nameservers 都必须在 root zone 中存在 NS 委派。
// 默认 NS 另外由本 PowerDNS 实例托管独立的 child zone。
func (h *DomainHandler) updateDomainNSRecordsInPowerDNS(domain *models.Domain, nameservers []string, isDefault bool) {
	if domain.RootDomain == nil {
		fmt.Printf("Warning: Cannot update NS records for domain %s: root domain not loaded\n", domain.FullDomain)
		return
	}

	rootDomain := domain.RootDomain.Domain
	subdomainFQDN := domain.FullDomain

	// 默认 NS：先确保 child zone 可提供权威应答，再发布父区委派。
	if isDefault {
		if err := dropForeignDS(h.pdns, rootDomain, subdomainFQDN); err != nil {
			fmt.Printf("Warning: Failed to remove custom-NS DS records for %s: %v\n", subdomainFQDN, err)
			return
		}
		defaultNS := ensureCanonicalNS([]string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2})
		if err := h.pdns.EnsureDelegatedZone(subdomainFQDN, rootDomain, defaultNS); err != nil {
			fmt.Printf("Warning: Failed to create delegated zone for %s in PowerDNS: %v\n", subdomainFQDN, err)
			return
		}
		fmt.Printf("Ensured delegated zone for %s with default nameservers: %v\n", subdomainFQDN, defaultNS)
		return
	}

	// 使用自定义 NS
	// 1. 先移除本地 child zone 的旧 DS，避免自定义服务被旧信任链标记为 BOGUS。
	if err := dropLocalDS(h.pdns, rootDomain, subdomainFQDN); err != nil {
		fmt.Printf("Warning: Failed to remove old DS records for %s: %v\n", subdomainFQDN, err)
		return
	}

	// 2. 删除子域名的独立 zone（如果存在）
	if err := h.pdns.DeleteZone(subdomainFQDN); err != nil {
		// zone 不存在不是错误
		if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "Could not find") {
			fmt.Printf("Warning: Failed to delete zone for %s in PowerDNS: %v\n", subdomainFQDN, err)
		}
	} else {
		fmt.Printf("Deleted zone for %s (using custom NS)\n", subdomainFQDN)
	}

	// 3. 用自定义 NS 替换父区委派。
	if err := h.pdns.SetDelegation(rootDomain, subdomainFQDN, ensureCanonicalNS(nameservers)); err != nil {
		fmt.Printf("Warning: Failed to set NS records for %s in PowerDNS: %v\n", subdomainFQDN, err)
	} else {
		fmt.Printf("Updated NS records for %s with custom nameservers: %v\n", subdomainFQDN, nameservers)
	}
}
