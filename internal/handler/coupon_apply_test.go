package handler

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"opendomain/internal/models"
)

func TestApplyCouponOncePerUser(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.Coupon{}, &models.CouponUsage{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	u := createTestUser(t, db, "apply@example.com", true)
	coupon := &models.Coupon{Code: "ONCE", DiscountType: "quota_increase", QuotaIncrease: 1,
		ValidFrom: time.Now().Add(-72 * time.Hour), IsActive: true}
	if err := db.Create(coupon).Error; err != nil {
		t.Fatalf("create coupon: %v", err)
	}

	h := NewCouponHandler(db, testConfig())
	r := gin.New()
	r.Use(withUser(u.ID))
	r.POST("/coupons/apply", h.ApplyCoupon)

	if code, body := doJSON(r, "POST", "/coupons/apply", gin.H{"code": "ONCE"}); code != http.StatusOK {
		t.Fatalf("first use = %d %v, want 200", code, body)
	}
	if code, body := doJSON(r, "POST", "/coupons/apply", gin.H{"code": "ONCE"}); code != http.StatusBadRequest {
		t.Fatalf("second use = %d %v, want 400", code, body)
	}

	var fresh models.User
	db.First(&fresh, u.ID)
	if fresh.DomainQuota != 3 {
		t.Fatalf("quota = %d, want 3", fresh.DomainQuota)
	}
}
