package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"opendomain/internal/config"
	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/pkg/timeutil"
)

type CouponHandler struct {
	db  *gorm.DB
	cfg *config.Config
}

func NewCouponHandler(db *gorm.DB, cfg *config.Config) *CouponHandler {
	return &CouponHandler{db: db, cfg: cfg}
}

// ListCoupons 获取优惠券列表 (管理员)
func (h *CouponHandler) ListCoupons(c *gin.Context) {
	var coupons []models.Coupon
	if err := h.db.Order("created_at DESC").Find(&coupons).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch coupons"})
		return
	}

	responses := make([]*models.CouponResponse, len(coupons))
	for i, coupon := range coupons {
		responses[i] = coupon.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{"coupons": responses})
}

// GetCoupon 获取单个优惠券信息
func (h *CouponHandler) GetCoupon(c *gin.Context) {
	couponID := c.Param("id")

	var coupon models.Coupon
	if err := h.db.First(&coupon, couponID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Coupon not found"})
		return
	}

	c.JSON(http.StatusOK, coupon.ToResponse())
}

// CreateCoupon 创建优惠券 (管理员)
func (h *CouponHandler) CreateCoupon(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.CouponCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证优惠券代码唯一性
	var existingCoupon models.Coupon
	if err := h.db.Where("code = ?", strings.ToUpper(req.Code)).First(&existingCoupon).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Coupon code already exists"})
		return
	}

	// 设置默认值
	validFrom := timeutil.Now()
	if req.ValidFrom != nil {
		validFrom = req.ValidFrom.Time
	}

	var validUntil *time.Time
	if req.ValidUntil != nil {
		t := req.ValidUntil.Time
		validUntil = &t
	}

	coupon := &models.Coupon{
		Code:          strings.ToUpper(req.Code),
		Description:   req.Description,
		DiscountType:  req.DiscountType,
		DiscountValue: req.DiscountValue,
		QuotaIncrease: req.QuotaIncrease,
		MaxUses:       req.MaxUses,
		UsedCount:     0,
		ValidFrom:     validFrom,
		ValidUntil:    validUntil,
		IsActive:      true,
		IsReusable:    req.IsReusable,
		CreatedBy:     &userID,
	}

	if err := h.db.Create(coupon).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create coupon"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Coupon created successfully",
		"coupon":  coupon.ToResponse(),
	})
}

// UpdateCoupon 更新优惠券 (管理员)
func (h *CouponHandler) UpdateCoupon(c *gin.Context) {
	couponID := c.Param("id")

	var coupon models.Coupon
	if err := h.db.First(&coupon, couponID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Coupon not found"})
		return
	}

	var req models.CouponUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新字段
	if req.Description != nil {
		coupon.Description = *req.Description
	}
	if req.DiscountValue != nil {
		coupon.DiscountValue = req.DiscountValue
	}
	if req.QuotaIncrease != nil {
		coupon.QuotaIncrease = *req.QuotaIncrease
	}
	if req.MaxUses != nil {
		coupon.MaxUses = *req.MaxUses
	}
	if req.ValidFrom != nil {
		t := req.ValidFrom.Time
		coupon.ValidFrom = t
	}
	if req.ValidUntil != nil {
		t := req.ValidUntil.Time
		coupon.ValidUntil = &t
	}
	if req.IsActive != nil {
		coupon.IsActive = *req.IsActive
	}
	if req.IsReusable != nil {
		coupon.IsReusable = *req.IsReusable
	}

	if err := h.db.Save(&coupon).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update coupon"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Coupon updated successfully",
		"coupon":  coupon.ToResponse(),
	})
}

// DeleteCoupon 删除优惠券 (管理员)
func (h *CouponHandler) DeleteCoupon(c *gin.Context) {
	couponID := c.Param("id")

	if err := h.db.Delete(&models.Coupon{}, couponID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete coupon"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Coupon deleted successfully"})
}

// ApplyCoupon 使用优惠券
func (h *CouponHandler) ApplyCoupon(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req models.CouponApplyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查找优惠券
	var coupon models.Coupon
	if err := h.db.Where("code = ?", strings.ToUpper(req.Code)).First(&coupon).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Coupon not found",
			"code":  strings.ToUpper(req.Code),
		})
		return
	}

	// 验证优惠券类型 - 此接口只允许额度增加类型的优惠券
	if coupon.DiscountType != "quota_increase" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "Only quota increase coupons can be applied here. Discount coupons should be used during domain registration or renewal.",
			"coupon_type":   coupon.DiscountType,
			"required_type": "quota_increase",
		})
		return
	}

	// 验证优惠券是否有效
	now := timeutil.Now()
	if !coupon.IsActive {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":     "Coupon is not active",
			"is_active": coupon.IsActive,
			"reason":    "This coupon has been disabled by administrator",
		})
		return
	}
	if now.Before(coupon.ValidFrom) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":        "Coupon is not yet valid",
			"valid_from":   coupon.ValidFrom.Format(time.RFC3339),
			"current_time": now.Format(time.RFC3339),
			"reason":       "coupon_not_yet_valid",
		})
		return
	}
	if coupon.ValidUntil != nil && now.After(*coupon.ValidUntil) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":        "Coupon has expired",
			"valid_until":  coupon.ValidUntil.Format(time.RFC3339),
			"current_time": now.Format(time.RFC3339),
			"reason":       "coupon_expired",
		})
		return
	}
	if coupon.MaxUses > 0 && coupon.UsedCount >= coupon.MaxUses {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":      "Coupon has reached maximum uses",
			"used_count": coupon.UsedCount,
			"max_uses":   coupon.MaxUses,
			"reason":     fmt.Sprintf("This coupon has been used %d out of %d times", coupon.UsedCount, coupon.MaxUses),
		})
		return
	}

	// 如果优惠券不可重复使用，检查用户是否已使用过
	if !coupon.IsReusable {
		var existingUsage models.CouponUsage
		if err := h.db.Where("coupon_id = ? AND user_id = ?", coupon.ID, userID).First(&existingUsage).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       "You have already used this coupon",
				"is_reusable": coupon.IsReusable,
				"used_at":     existingUsage.UsedAt.Format("2006-01-02 15:04:05"),
				"reason":      "This coupon can only be used once per user. You used it on " + existingUsage.UsedAt.Format("2006-01-02 15:04:05"),
			})
			return
		}
	}

	benefitApplied := fmt.Sprintf("Domain quota increased by %d", coupon.QuotaIncrease)

	// 开始事务
	tx := h.db.Begin()

	// 原子增加配额，避免整行保存覆盖并发写入
	if err := tx.Model(&models.User{}).Where("id = ?", userID).
		UpdateColumn("domain_quota", gorm.Expr("domain_quota + ?", coupon.QuotaIncrease)).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to apply coupon"})
		return
	}

	// 增加使用次数
	if err := tx.Model(&coupon).UpdateColumn("used_count", gorm.Expr("used_count + ?", 1)).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update coupon"})
		return
	}

	// 记录使用历史
	usage := &models.CouponUsage{
		CouponID:       coupon.ID,
		UserID:         userID,
		UsedAt:         timeutil.Now(),
		BenefitApplied: benefitApplied,
	}
	if err := tx.Create(usage).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record usage"})
		return
	}

	var user models.User
	if err := tx.Select("domain_quota").First(&user, userID).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}

	tx.Commit()

	c.JSON(http.StatusOK, gin.H{
		"message":         "Coupon applied successfully",
		"benefit_applied": benefitApplied,
		"new_quota":       user.DomainQuota,
	})
}

// GetMyCouponUsage 获取我的优惠券使用记录
func (h *CouponHandler) GetMyCouponUsage(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var usages []models.CouponUsage
	if err := h.db.Preload("Coupon").Where("user_id = ?", userID).Order("used_at DESC").Find(&usages).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch usage history"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"usages": usages})
}
