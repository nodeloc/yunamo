package handler

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"opendomain/internal/models"
)

func newQuotaTestDB(t *testing.T) (*gorm.DB, *models.RootDomain) {
	t.Helper()
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.RootDomain{}, &models.Domain{}, &models.Coupon{}, &models.CouponUsage{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	root := &models.RootDomain{
		Domain:                "loc.cc",
		Nameservers:           `["ns1.example.com","ns2.example.com"]`,
		UseDefaultNameservers: true,
		IsActive:              true,
		IsFree:                true,
		MinUserLevel:          "normal",
		MinLength:             3,
		MaxLength:             63,
	}
	if err := db.Create(root).Error; err != nil {
		t.Fatalf("create root domain: %v", err)
	}
	return db, root
}

func makeQuotaCoupon(t *testing.T, db *gorm.DB, code string, increase int) *models.Coupon {
	t.Helper()
	c := &models.Coupon{
		Code:          code,
		DiscountType:  "quota_increase",
		QuotaIncrease: increase,
		MaxUses:       100,
		ValidFrom:     time.Now().Add(-time.Hour),
		IsActive:      true,
	}
	if err := db.Create(c).Error; err != nil {
		t.Fatalf("create coupon: %v", err)
	}
	return c
}

func addActiveDomains(t *testing.T, db *gorm.DB, userID, rootID uint, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		d := &models.Domain{
			UserID:                userID,
			RootDomainID:          rootID,
			Subdomain:             "held" + string(rune('a'+i)),
			FullDomain:            "held" + string(rune('a'+i)) + ".loc.cc",
			Status:                "active",
			RegisteredAt:          time.Now(),
			ExpiresAt:             time.Now().AddDate(1, 0, 0),
			UseDefaultNameservers: true,
		}
		if err := db.Create(d).Error; err != nil {
			t.Fatalf("create domain: %v", err)
		}
	}
}

func quotaRouter(h *DomainHandler, userID uint) *gin.Engine {
	r := gin.New()
	r.Use(withUser(userID))
	r.POST("/api/domains", h.RegisterDomain)
	return r
}

// A user already over quota must not be able to sneak in extra domains with a
// coupon that only adds +1 quota. This is the "over quota => unlimited domains"
// bug: the old code only checked `count >= quota` and never verified that the
// coupon raised the limit above the current usage.
func TestRegisterDomainOverQuotaSmallCouponRejected(t *testing.T) {
	db, root := newQuotaTestDB(t)
	u := createTestUser(t, db, "overquota@example.com", true, func(x *models.User) { x.DomainQuota = 2 })
	addActiveDomains(t, db, u.ID, root.ID, 3) // 3 held, quota 2
	makeQuotaCoupon(t, db, "PLUS1", 1)

	h := NewDomainHandler(db, testConfig())
	r := quotaRouter(h, u.ID)

	code, body := doJSON(r, "POST", "/api/domains", gin.H{
		"subdomain": "sneaky", "root_domain_id": root.ID, "coupon_code": "PLUS1",
	})
	if code != http.StatusForbidden || body["quota_exceeded"] != true {
		t.Fatalf("over-quota + small coupon = %d %v, want 403 quota_exceeded", code, body)
	}
	var count int64
	db.Model(&models.Domain{}).Where("user_id = ?", u.ID).Count(&count)
	if count != 3 {
		t.Fatalf("domain count = %d, want 3 (no domain must be created)", count)
	}
}

// A coupon that adds enough quota does let an over-quota user register.
func TestRegisterDomainOverQuotaBigCouponAllowed(t *testing.T) {
	db, root := newQuotaTestDB(t)
	u := createTestUser(t, db, "bigcoupon@example.com", true, func(x *models.User) { x.DomainQuota = 2 })
	addActiveDomains(t, db, u.ID, root.ID, 3)
	makeQuotaCoupon(t, db, "PLUS5", 5)

	h := NewDomainHandler(db, testConfig())
	r := quotaRouter(h, u.ID)

	code, body := doJSON(r, "POST", "/api/domains", gin.H{
		"subdomain": "allowed", "root_domain_id": root.ID, "coupon_code": "PLUS5",
	})
	if code != http.StatusOK {
		t.Fatalf("over-quota + big coupon = %d %v, want 200", code, body)
	}
	var fresh models.User
	db.First(&fresh, u.ID)
	if fresh.DomainQuota != 7 {
		t.Fatalf("quota = %d, want 7 (2 + 5)", fresh.DomainQuota)
	}
}

// At the limit with a +1 coupon the user gets exactly one more domain.
func TestRegisterDomainAtLimitUsesCouponOnce(t *testing.T) {
	db, root := newQuotaTestDB(t)
	u := createTestUser(t, db, "atlimit@example.com", true, func(x *models.User) { x.DomainQuota = 2 })
	addActiveDomains(t, db, u.ID, root.ID, 2)
	makeQuotaCoupon(t, db, "ONCE", 1)

	h := NewDomainHandler(db, testConfig())
	r := quotaRouter(h, u.ID)

	code, body := doJSON(r, "POST", "/api/domains", gin.H{
		"subdomain": "first", "root_domain_id": root.ID, "coupon_code": "ONCE",
	})
	if code != http.StatusOK {
		t.Fatalf("first use = %d %v, want 200", code, body)
	}

	// Quota is now 3 and 3 domains are held, so the same coupon must be rejected.
	code, body = doJSON(r, "POST", "/api/domains", gin.H{
		"subdomain": "second", "root_domain_id": root.ID, "coupon_code": "ONCE",
	})
	if code != http.StatusBadRequest {
		t.Fatalf("reuse of quota coupon = %d %v, want 400", code, body)
	}
	var count int64
	db.Model(&models.Domain{}).Where("user_id = ?", u.ID).Count(&count)
	if count != 3 {
		t.Fatalf("domain count = %d, want 3", count)
	}
}

// Under quota, a supplied coupon is not consumed and quota does not change.
func TestRegisterDomainUnderQuotaDoesNotConsumeCoupon(t *testing.T) {
	db, root := newQuotaTestDB(t)
	u := createTestUser(t, db, "under@example.com", true, func(x *models.User) { x.DomainQuota = 5 })
	makeQuotaCoupon(t, db, "SPARE", 3)

	h := NewDomainHandler(db, testConfig())
	r := quotaRouter(h, u.ID)

	code, body := doJSON(r, "POST", "/api/domains", gin.H{
		"subdomain": "freeone", "root_domain_id": root.ID, "coupon_code": "SPARE",
	})
	if code != http.StatusOK {
		t.Fatalf("under quota = %d %v, want 200", code, body)
	}
	var fresh models.User
	db.First(&fresh, u.ID)
	if fresh.DomainQuota != 5 {
		t.Fatalf("quota = %d, want 5 (coupon must not be consumed)", fresh.DomainQuota)
	}
	var usages int64
	db.Model(&models.CouponUsage{}).Where("user_id = ?", u.ID).Count(&usages)
	if usages != 0 {
		t.Fatalf("coupon usages = %d, want 0", usages)
	}
}

// Using several different +1 coupons must not let an over-quota account creep
// forward one domain at a time. This is the reported "use multiple coupons"
// variant of the bypass.
func TestRegisterDomainOverQuotaMultipleCouponsRejected(t *testing.T) {
	db, root := newQuotaTestDB(t)
	u := createTestUser(t, db, "multicoupon@example.com", true, func(x *models.User) { x.DomainQuota = 2 })
	addActiveDomains(t, db, u.ID, root.ID, 4) // 4 held, quota 2
	makeQuotaCoupon(t, db, "PLUS1-A", 1)
	makeQuotaCoupon(t, db, "PLUS1-B", 1)

	h := NewDomainHandler(db, testConfig())
	r := quotaRouter(h, u.ID)

	for i, code := range []string{"PLUS1-A", "PLUS1-B"} {
		status, body := doJSON(r, "POST", "/api/domains", gin.H{
			"subdomain": fmt.Sprintf("multi%d", i), "root_domain_id": root.ID, "coupon_code": code,
		})
		if status != http.StatusForbidden || body["quota_exceeded"] != true {
			t.Fatalf("coupon %s = %d %v, want 403 quota_exceeded", code, status, body)
		}
	}

	var count int64
	db.Model(&models.Domain{}).Where("user_id = ?", u.ID).Count(&count)
	if count != 4 {
		t.Fatalf("domain count = %d, want 4 (no domain must be created)", count)
	}
	var used int64
	db.Model(&models.CouponUsage{}).Where("user_id = ?", u.ID).Count(&used)
	if used != 0 {
		t.Fatalf("coupon usages = %d, want 0 (rejected coupons must not be consumed)", used)
	}
}
