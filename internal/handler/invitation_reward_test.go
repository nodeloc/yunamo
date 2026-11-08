package handler

import (
	"net/http"
	"testing"

	"opendomain/internal/models"
)

func TestInviteRewardWaitsForEmailVerification(t *testing.T) {
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.SystemSetting{}, &models.Invitation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mailer, fake := syncMailer()
	h := NewUserHandler(db, nil, testConfig(), mailer)
	r := newUserRouter(h, 0)

	inviter := createTestUser(t, db, "inviter@example.com", true, func(u *models.User) { u.InviteCode = "INVITE1" })

	code, _ := doJSON(r, http.MethodPost, "/api/auth/register", map[string]interface{}{
		"username": "newbie", "email": "newbie@example.com", "password": "secret123", "invite_code": "INVITE1",
	})
	if code != http.StatusOK {
		t.Fatalf("register status %d", code)
	}

	var invitee models.User
	db.Where("email = ?", "newbie@example.com").First(&invitee)
	var inv models.Invitation
	if err := db.Where("invitee_id = ?", invitee.ID).First(&inv).Error; err != nil {
		t.Fatalf("invitation not recorded: %v", err)
	}
	var inviterNow models.User
	db.First(&inviterNow, inviter.ID)
	if inv.RewardGiven || inviterNow.DomainQuota != 2 || inviterNow.SuccessfulInvites != 0 || invitee.DomainQuota != 2 {
		t.Fatalf("reward granted before verification: given=%v inviterQuota=%d successful=%d inviteeQuota=%d",
			inv.RewardGiven, inviterNow.DomainQuota, inviterNow.SuccessfulInvites, invitee.DomainQuota)
	}
	if inviterNow.TotalInvites != 1 {
		t.Fatalf("total_invites = %d, want 1", inviterNow.TotalInvites)
	}

	mails := fake.all()
	if len(mails) == 0 {
		t.Fatal("no verification mail sent")
	}
	token := tokenFromMail(t, mails[len(mails)-1])
	if code, _ := doJSON(r, http.MethodPost, "/api/auth/verify-email", map[string]string{"token": token}); code != http.StatusOK {
		t.Fatalf("verify status %d", code)
	}

	db.First(&inviterNow, inviter.ID)
	db.First(&invitee, invitee.ID)
	db.First(&inv, inv.ID)
	if !inv.RewardGiven || inviterNow.DomainQuota != 3 || inviterNow.SuccessfulInvites != 1 || invitee.DomainQuota != 3 {
		t.Fatalf("reward not granted after verification: given=%v inviterQuota=%d successful=%d inviteeQuota=%d",
			inv.RewardGiven, inviterNow.DomainQuota, inviterNow.SuccessfulInvites, invitee.DomainQuota)
	}

	// 重复发放必须是空操作
	if err := grantInvitationReward(db, invitee.ID); err != nil {
		t.Fatal(err)
	}
	db.First(&inviterNow, inviter.ID)
	if inviterNow.DomainQuota != 3 {
		t.Fatalf("reward granted twice: inviter quota %d", inviterNow.DomainQuota)
	}
}
