package handler

import (
	"errors"
	"testing"

	"opendomain/internal/models"
)

func TestOAuthDoesNotLinkUnverifiedLocalAccount(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := NewOAuthHandler(db, testConfig())

	// 攻击者预先用受害者邮箱注册、未验证
	squatter := createTestUser(t, db, "victim@example.com", false)

	_, err := h.findOrCreateOAuthUser("github", "gh-1", "victim@example.com", "victim", "", "1.2.3.4", "normal", 2)
	if !errors.Is(err, errOAuthEmailUnverified) {
		t.Fatalf("expected errOAuthEmailUnverified, got %v", err)
	}
	var reloaded models.User
	if err := db.First(&reloaded, squatter.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.OAuthID != nil {
		t.Fatalf("unverified account was linked to OAuth identity")
	}
}

func TestOAuthLinksVerifiedLocalAccount(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := NewOAuthHandler(db, testConfig())
	owner := createTestUser(t, db, "owner@example.com", true)

	got, err := h.findOrCreateOAuthUser("github", "gh-2", "owner@example.com", "owner", "", "1.2.3.4", "normal", 2)
	if err != nil {
		t.Fatalf("link verified account: %v", err)
	}
	if got.ID != owner.ID {
		t.Fatalf("linked to user %d, want %d", got.ID, owner.ID)
	}
}
