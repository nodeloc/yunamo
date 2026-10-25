package handler

import (
	"testing"

	"opendomain/internal/models"
)

func TestNodelocReloginKeepsBonusQuota(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.SystemSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := NewOAuthHandler(db, testConfig())

	cases := []struct {
		name      string
		fromLevel string
		toLevel   string
		quota     int
		want      int
	}{
		{"same level", "basic", "basic", 3 + 3, 3 + 3},
		{"upgrade", "basic", "member", 3 + 3, 5 + 3},
		{"downgrade", "member", "basic", 5 + 3, 3 + 3},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oauthID := string(rune('a' + i))
			u := createTestUser(t, db, tc.name+"@example.com", true, func(u *models.User) {
				u.Provider = "nodeloc"
				u.OAuthID = &oauthID
				u.UserLevel = tc.fromLevel
				u.DomainQuota = tc.quota
			})

			if _, err := h.findOrCreateOAuthUser("nodeloc", oauthID, u.Email, u.Username, "", "127.0.0.1", tc.toLevel, GetQuotaForLevel(db, tc.toLevel)); err != nil {
				t.Fatalf("login: %v", err)
			}

			var got models.User
			db.First(&got, u.ID)
			if got.DomainQuota != tc.want || got.UserLevel != tc.toLevel {
				t.Fatalf("got quota %d level %s, want %d %s", got.DomainQuota, got.UserLevel, tc.want, tc.toLevel)
			}
		})
	}
}
