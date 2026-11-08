package models

import (
	"time"

	"gorm.io/gorm"
)

// User 用户模型
type User struct {
	ID            uint           `gorm:"primarykey" json:"id"`
	Username      string         `gorm:"size:50;not null;uniqueIndex" json:"username"`
	Email         string         `gorm:"size:100;not null;uniqueIndex" json:"email"`
	EmailVerified bool           `gorm:"default:false" json:"email_verified"`
	Phone         *string        `gorm:"size:20" json:"phone,omitempty"`
	PhoneVerified bool           `gorm:"default:false" json:"phone_verified"`
	PasswordHash  string         `gorm:"size:255" json:"-"`
	Provider      string         `gorm:"size:20;default:local" json:"provider"`
	OAuthID       *string        `gorm:"column:oauth_id;size:255" json:"-"`
	Avatar        *string        `gorm:"size:255" json:"avatar,omitempty"`
	RealName      *string        `gorm:"size:50" json:"real_name,omitempty"`
	IsVerified    bool           `gorm:"default:false" json:"is_verified"`
	IsAdmin       bool           `gorm:"default:false" json:"is_admin"`
	UserLevel     string         `gorm:"size:20;default:normal" json:"user_level"` // normal/basic/member/regular/leader
	DomainQuota      int            `gorm:"default:2" json:"domain_quota"`
	InviteCode       string         `gorm:"size:20;not null;uniqueIndex" json:"invite_code"`
	InvitedBy        *uint          `json:"invited_by,omitempty"`
	TotalInvites     int            `gorm:"default:0" json:"total_invites"`
	SuccessfulInvites int           `gorm:"default:0" json:"successful_invites"`
	Status           string         `gorm:"size:20;default:active" json:"status"` // active/frozen/banned
	LastLoginAt   *time.Time     `json:"last_login_at,omitempty"`
	LastLoginIP   *string        `gorm:"size:45" json:"last_login_ip,omitempty"`
	// PasswordChangedAt 之前签发的 token 全部失效
	PasswordChangedAt *time.Time `json:"-"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName 指定表名
func (User) TableName() string {
	return "users"
}

// UserRegisterRequest 用户注册请求
type UserRegisterRequest struct {
	Username  string  `json:"username" binding:"required,min=3,max=50"`
	Email     string  `json:"email" binding:"required,email"`
	Password  string  `json:"password" binding:"required,min=6"`
	InviteCode *string `json:"invite_code,omitempty"`
}

// UserLoginRequest 用户登录请求
type UserLoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// UserResponse 用户响应
type UserResponse struct {
	ID                uint       `json:"id"`
	Username          string     `json:"username"`
	Email             string     `json:"email"`
	EmailVerified     bool       `json:"email_verified"`
	Avatar            *string    `json:"avatar,omitempty"`
	IsAdmin           bool       `json:"is_admin"`
	UserLevel         string     `json:"user_level"`
	DomainQuota       int        `json:"domain_quota"`
	InviteCode        string     `json:"invite_code"`
	TotalInvites      int        `json:"total_invites"`
	SuccessfulInvites int        `json:"successful_invites"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
}

// ToResponse 转换为响应格式
func (u *User) ToResponse() *UserResponse {
	return &UserResponse{
		ID:                u.ID,
		Username:          u.Username,
		Email:             u.Email,
		EmailVerified:     u.EmailVerified,
		Avatar:            u.Avatar,
		IsAdmin:           u.IsAdmin,
		UserLevel:         u.UserLevel,
		DomainQuota:       u.DomainQuota,
		InviteCode:        u.InviteCode,
		TotalInvites:      u.TotalInvites,
		SuccessfulInvites: u.SuccessfulInvites,
		Status:            u.Status,
		CreatedAt:         u.CreatedAt,
		LastLoginAt:       u.LastLoginAt,
	}
}
