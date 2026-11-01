package models

import (
	"time"

	"gorm.io/gorm"
)

// DNSRecord DNS 记录模型
type DNSRecord struct {
	ID              uint           `gorm:"primarykey" json:"id"`
	DomainID        uint           `gorm:"not null;index" json:"domain_id"`
	Name            string         `gorm:"size:255;not null" json:"name"`
	Type            string         `gorm:"size:20;not null" json:"type"` // A, AAAA, CNAME, ALIAS, MX, TXT, NS, SRV, CAA
	Content         string         `gorm:"type:text;not null" json:"content"`
	TTL             int            `gorm:"default:3600" json:"ttl"`
	Priority        *int           `json:"priority,omitempty"` // For MX and SRV records
	IsActive        bool           `gorm:"default:true" json:"is_active"`
	SyncedToPowerDNS bool          `gorm:"column:synced_to_powerdns;default:false" json:"synced_to_powerdns"`
	SyncError       *string        `gorm:"type:text" json:"sync_error,omitempty"`
	LastSyncedAt    *time.Time     `json:"last_synced_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`

	Domain *Domain `gorm:"foreignKey:DomainID" json:"domain,omitempty"`
}

// TableName 指定表名
func (DNSRecord) TableName() string {
	return "dns_records"
}

// DNSRecordCreateRequest 创建 DNS 记录请求
type DNSRecordCreateRequest struct {
	Name     string `json:"name" binding:"required"`
	Type     string `json:"type" binding:"required,oneof=A AAAA CNAME ALIAS MX TXT NS SRV CAA"`
	Content  string `json:"content" binding:"required"`
	TTL      int    `json:"ttl" binding:"min=60,max=86400"`
	Priority *int   `json:"priority,omitempty"`
}

// DNSRecordUpdateRequest 更新 DNS 记录请求
type DNSRecordUpdateRequest struct {
	Name     *string `json:"name,omitempty"`
	Type     *string `json:"type,omitempty" binding:"omitempty,oneof=A AAAA CNAME ALIAS MX TXT NS SRV CAA"`
	Content  *string `json:"content,omitempty"`
	TTL      *int    `json:"ttl,omitempty"`
	Priority *int    `json:"priority,omitempty"`
	IsActive *bool   `json:"is_active,omitempty"`
}

// DNSRecordResponse DNS 记录响应
type DNSRecordResponse struct {
	ID               uint       `json:"id"`
	DomainID         uint       `json:"domain_id"`
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	Content          string     `json:"content"`
	TTL              int        `json:"ttl"`
	Priority         *int       `json:"priority,omitempty"`
	IsActive         bool       `json:"is_active"`
	SyncedToPowerDNS bool       `json:"synced_to_powerdns"`
	SyncError        *string    `json:"sync_error,omitempty"`
	LastSyncedAt     *time.Time `json:"last_synced_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// ToResponse 转换为响应格式
func (d *DNSRecord) ToResponse() *DNSRecordResponse {
	return &DNSRecordResponse{
		ID:               d.ID,
		DomainID:         d.DomainID,
		Name:             d.Name,
		Type:             d.Type,
		Content:          d.Content,
		TTL:              d.TTL,
		Priority:         d.Priority,
		IsActive:         d.IsActive,
		SyncedToPowerDNS: d.SyncedToPowerDNS,
		SyncError:        d.SyncError,
		LastSyncedAt:     d.LastSyncedAt,
		CreatedAt:        d.CreatedAt,
		UpdatedAt:        d.UpdatedAt,
	}
}
