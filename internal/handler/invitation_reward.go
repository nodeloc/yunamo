package handler

import (
	"errors"

	"gorm.io/gorm"

	"opendomain/internal/models"
)

// grantInvitationReward 在被邀请人证明邮箱归属后发放邀请奖励：
// 邀请人 +1 配额、+1 成功邀请，被邀请人 +1 配额。
// 用条件更新 reward_given=false→true 保证每条邀请只发放一次（重复验证、并发请求都安全）。
func grantInvitationReward(tx *gorm.DB, inviteeID uint) error {
	var inv models.Invitation
	err := tx.Where("invitee_id = ? AND reward_given = ?", inviteeID, false).First(&inv).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	res := tx.Model(&models.Invitation{}).
		Where("id = ? AND reward_given = ?", inv.ID, false).
		Update("reward_given", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return nil // 已被并发请求发放
	}

	if err := tx.Model(&models.User{}).Where("id = ?", inv.InviterID).Updates(map[string]interface{}{
		"domain_quota":       gorm.Expr("domain_quota + ?", 1),
		"successful_invites": gorm.Expr("successful_invites + ?", 1),
	}).Error; err != nil {
		return err
	}
	return tx.Model(&models.User{}).Where("id = ?", inviteeID).
		UpdateColumn("domain_quota", gorm.Expr("domain_quota + ?", 1)).Error
}
