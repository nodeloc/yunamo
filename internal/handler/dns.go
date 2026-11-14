package handler

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"opendomain/internal/config"
	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/pkg/powerdns"
	"opendomain/pkg/timeutil"
)

type DNSHandler struct {
	db   *gorm.DB
	cfg  *config.Config
	pdns *powerdns.Client
}

func NewDNSHandler(db *gorm.DB, cfg *config.Config) *DNSHandler {
	return &DNSHandler{
		db:   db,
		cfg:  cfg,
		pdns: powerdns.NewClient(cfg.PowerDNS.APIURL, cfg.PowerDNS.APIKey),
	}
}

// ensureCanonicalNS 确保 nameserver 是规范格式（以 . 结尾）
func ensureCanonicalNS(nameservers []string) []string {
	canonical := make([]string, 0, len(nameservers))
	for _, ns := range nameservers {
		ns = strings.ToLower(strings.TrimSpace(ns))
		if ns == "" {
			continue
		}
		if !strings.HasSuffix(ns, ".") {
			ns += "."
		}
		canonical = append(canonical, ns)
	}
	return canonical
}

// nameserverHostnameRe matches a hostname made of DNS labels (RFC 1123) with
// at least two labels; a trailing dot is stripped before matching.
// dnsTargetRe 匹配 CNAME/ALIAS 目标。下划线不是合法主机名字符，但 ACM、DKIM 等
// 服务的 CNAME 目标会用到，所以这里放行。
var dnsTargetRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}(\.[A-Za-z0-9_-]{1,63})*$`)

var nameserverHostnameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// normalizeNameservers trims whitespace, lowercases, strips the trailing dot,
// drops duplicates and rejects anything that is not a valid hostname. This is
// the form stored in the database; PowerDNS refuses records with stray
// whitespace such as "dns1.example.com\t.".
func normalizeNameservers(nameservers []string) ([]string, error) {
	seen := make(map[string]bool, len(nameservers))
	out := make([]string, 0, len(nameservers))
	for _, raw := range nameservers {
		ns := strings.ToLower(strings.TrimSpace(raw))
		ns = strings.TrimSuffix(ns, ".")
		if ns == "" {
			continue
		}
		if len(ns) > 253 || !nameserverHostnameRe.MatchString(ns) {
			return nil, fmt.Errorf("invalid nameserver hostname: %q", strings.TrimSpace(raw))
		}
		if seen[ns] {
			continue
		}
		seen[ns] = true
		out = append(out, ns)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one nameserver is required")
	}
	return out, nil
}

// sameNameservers compares nameserver sets case-insensitively and ignores
// presentation-only trailing dots and ordering.
func sameNameservers(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, ns := range left {
		key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns), "."))
		counts[key]++
	}
	for _, ns := range right {
		key := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns), "."))
		if counts[key] == 0 {
			return false
		}
		counts[key]--
	}
	return true
}

// ListRecords 获取域名的 DNS 记录列表
func (h *DNSHandler) ListRecords(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("domainId")

	// 验证域名所有权
	var domain models.Domain
	if err := h.db.First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// 获取 DNS 记录
	var records []models.DNSRecord
	if err := h.db.Where("domain_id = ?", domainID).Order("created_at DESC").Find(&records).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch DNS records"})
		return
	}

	responses := make([]*models.DNSRecordResponse, len(records))
	for i, record := range records {
		responses[i] = record.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{"records": responses})
}

// GetRecord 获取单个 DNS 记录
func (h *DNSHandler) GetRecord(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("domainId")
	recordID := c.Param("recordId")

	// 验证域名所有权
	var domain models.Domain
	if err := h.db.First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	// 获取 DNS 记录
	var record models.DNSRecord
	if err := h.db.Where("id = ? AND domain_id = ?", recordID, domainID).First(&record).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "DNS record not found"})
		return
	}

	c.JSON(http.StatusOK, record.ToResponse())
}

// CreateRecord 创建 DNS 记录
func (h *DNSHandler) CreateRecord(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("domainId")

	// 验证域名所有权
	var domain models.Domain
	if err := h.db.Preload("RootDomain").First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.Status == "abuse" {
		c.JSON(http.StatusForbidden, gin.H{"error": "This domain has been flagged for abuse. All operations are disabled."})
		return
	}

	// 检查是否使用自定义 nameservers
	if !domain.UseDefaultNameservers {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "Cannot manage DNS records for domains using custom nameservers. Please manage DNS records on your custom nameserver.",
			"use_custom_ns": true,
		})
		return
	}

	var req models.DNSRecordCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 设置默认 TTL
	if req.TTL == 0 {
		req.TTL = 3600
	}

	// MX 记录默认优先级
	if req.Type == "MX" && req.Priority == nil {
		defaultPriority := 10
		req.Priority = &defaultPriority
	}

	// 规范化用户输入（去除 CNAME/ALIAS 首尾引号等）
	req.Content = normalizeUserContent(req.Type, req.Content)

	// 验证记录内容
	if err := validateDNSRecord(req.Type, req.Content); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// CNAME/ALIAS 冲突检查：CNAME/ALIAS 不能与同名的其他记录共存（仅检查活跃记录）
	var conflictCount int64
	if req.Type == "CNAME" || req.Type == "ALIAS" {
		h.db.Model(&models.DNSRecord{}).Where("domain_id = ? AND name = ? AND type NOT IN ? AND is_active = ?", domain.ID, req.Name, []string{"CNAME", "ALIAS"}, true).Count(&conflictCount)
		if conflictCount > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "CNAME/ALIAS record cannot coexist with other record types at the same name"})
			return
		}
	} else {
		h.db.Model(&models.DNSRecord{}).Where("domain_id = ? AND name = ? AND type IN ? AND is_active = ?", domain.ID, req.Name, []string{"CNAME", "ALIAS"}, true).Count(&conflictCount)
		if conflictCount > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot add this record because a CNAME/ALIAS record already exists at the same name"})
			return
		}
	}

	// 创建 DNS 记录
	record := &models.DNSRecord{
		DomainID:         domain.ID,
		Name:             req.Name,
		Type:             req.Type,
		Content:          req.Content,
		TTL:              req.TTL,
		Priority:         req.Priority,
		IsActive:         true,
		SyncedToPowerDNS: false,
	}

	if err := h.db.Create(record).Error; err != nil {
		fmt.Printf("Failed to create DNS record: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create DNS record: %v", err)})
		return
	}

	// 同步到 PowerDNS
	go h.syncRecordSetToPowerDNS(record, &domain)

	c.JSON(http.StatusOK, gin.H{
		"message": "DNS record created successfully",
		"record":  record.ToResponse(),
	})
}

// UpdateRecord 更新 DNS 记录
func (h *DNSHandler) UpdateRecord(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("domainId")
	recordID := c.Param("recordId")

	// 验证域名所有权
	var domain models.Domain
	if err := h.db.First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.Status == "abuse" {
		c.JSON(http.StatusForbidden, gin.H{"error": "This domain has been flagged for abuse. All operations are disabled."})
		return
	}

	// 获取 DNS 记录
	var record models.DNSRecord
	if err := h.db.Where("id = ? AND domain_id = ?", recordID, domainID).First(&record).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "DNS record not found"})
		return
	}

	// 检查是否使用自定义 nameservers
	if !domain.UseDefaultNameservers {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "Cannot manage DNS records for domains using custom nameservers. Please manage DNS records on your custom nameserver.",
			"use_custom_ns": true,
		})
		return
	}

	var req models.DNSRecordUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 更新字段
	oldType, oldContent := record.Type, record.Content
	if req.Name != nil {
		record.Name = *req.Name
	}
	if req.Type != nil {
		record.Type = *req.Type
	}
	if req.Content != nil {
		record.Content = normalizeUserContent(record.Type, *req.Content)
	}
	if req.TTL != nil {
		record.TTL = *req.TTL
	}
	if req.Priority != nil {
		record.Priority = req.Priority
	}
	if req.IsActive != nil {
		record.IsActive = *req.IsActive
	}

	// 内容变化时才校验，避免历史记录连 TTL 都改不了、也无法禁用
	if record.Type != oldType || record.Content != oldContent {
		if err := validateDNSRecord(record.Type, record.Content); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	// 标记为未同步
	record.SyncedToPowerDNS = false

	if err := h.db.Save(&record).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update DNS record"})
		return
	}

	// 同步到 PowerDNS
	h.db.Preload("RootDomain").First(&domain, domain.ID)
	go h.syncRecordSetToPowerDNS(&record, &domain)

	c.JSON(http.StatusOK, gin.H{
		"message": "DNS record updated successfully",
		"record":  record.ToResponse(),
	})
}

// DeleteRecord 删除 DNS 记录
func (h *DNSHandler) DeleteRecord(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("domainId")
	recordID := c.Param("recordId")

	// 验证域名所有权
	var domain models.Domain
	if err := h.db.First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.Status == "abuse" {
		c.JSON(http.StatusForbidden, gin.H{"error": "This domain has been flagged for abuse. All operations are disabled."})
		return
	}

	// 获取 DNS 记录
	var record models.DNSRecord
	if err := h.db.Where("id = ? AND domain_id = ?", recordID, domainID).First(&record).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "DNS record not found"})
		return
	}

	// 检查是否使用自定义 nameservers
	if !domain.UseDefaultNameservers {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "Cannot manage DNS records for domains using custom nameservers. Please manage DNS records on your custom nameserver.",
			"use_custom_ns": true,
		})
		return
	}

	// 删除 DNS 记录
	if err := h.db.Delete(&record).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete DNS record"})
		return
	}

	// 从 PowerDNS 删除记录
	h.db.Preload("RootDomain").First(&domain, domain.ID)
	go h.deleteRecordFromPowerDNS(&record, &domain)

	c.JSON(http.StatusOK, gin.H{"message": "DNS record deleted successfully"})
}

// normalizeUserContent 规范化用户输入的 DNS 记录内容，存入 DB 前清理
// CNAME/ALIAS: 去除用户可能误加的首尾引号和尾点
func normalizeUserContent(recordType, content string) string {
	switch recordType {
	case "CNAME", "ALIAS", "NS":
		// 去除首尾的单引号、双引号、反引号
		content = strings.Trim(content, "'\"` ")
		// 去除尾点（DB 存储不带尾点，推送时再加）
		content = strings.TrimSuffix(content, ".")
	}
	return content
}

// normalizePowerDNSContent 确保需要 FQDN 的记录类型在内容末尾有尾点
// PowerDNS 要求 ALIAS、CNAME、NS、MX 等的目标为绝对域名（以 . 结尾）
// PowerDNS 要求 TXT 内容用双引号包裹；CAA 的 value 段也需要引号
func normalizePowerDNSContent(recordType, content string) string {
	switch recordType {
	case "ALIAS", "CNAME", "NS", "MX":
		if content != "" && !strings.HasSuffix(content, ".") {
			return content + "."
		}
	case "TXT", "SPF":
		return ensureTXTQuoted(content)
	case "CAA":
		return ensureCAAQuoted(content)
	}
	return content
}

// ensureTXTQuoted 确保 TXT/SPF 内容被双引号包裹
// 用户输入: v=spf1 include:example.com ~all
// 推送给 PowerDNS: "v=spf1 include:example.com ~all"
func ensureTXTQuoted(content string) string {
	if strings.HasPrefix(content, "\"") && strings.HasSuffix(content, "\"") {
		return content // 已经有引号，不重复处理
	}
	// 转义内部双引号再包裹
	content = strings.ReplaceAll(content, "\\\"", "\"")
	content = strings.ReplaceAll(content, "\"", "\\\"")
	return "\"" + content + "\""
}

// ensureCAAQuoted 确保 CAA value 段有引号
// 用户输入: 0 issue letsencrypt.org
// 推送给 PowerDNS: 0 issue "letsencrypt.org"
func ensureCAAQuoted(content string) string {
	parts := strings.Fields(content)
	if len(parts) < 3 {
		return content
	}
	value := strings.Join(parts[2:], " ")
	if strings.HasPrefix(value, "\"") {
		return content // 已经有引号
	}
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return parts[0] + " " + parts[1] + " \"" + value + "\""
}

// validateDNSRecord 验证 DNS 记录内容
func validateDNSRecord(recordType, content string) error {
	// 基本验证，可以根据需要扩展
	switch recordType {
	case "A":
		// IPv4 地址验证
		if !isValidIPv4(content) {
			return fmt.Errorf("invalid IPv4 address")
		}
	case "AAAA":
		// IPv6 地址验证
		if !isValidIPv6(content) {
			return fmt.Errorf("invalid IPv6 address")
		}
	case "CNAME", "ALIAS":
		if content == "" {
			return fmt.Errorf("content cannot be empty")
		}
		if !isValidDNSTarget(content) {
			return fmt.Errorf("invalid domain name")
		}
	case "NS":
		if content == "" {
			return fmt.Errorf("content cannot be empty")
		}
		// NS 目标是主机名，不能带下划线
		if !isValidHostnameTarget(content) {
			return fmt.Errorf("invalid domain name")
		}
	case "MX":
		if content == "" {
			return fmt.Errorf("content cannot be empty")
		}
		// RFC 7505 null MX：单个 "." 表示该域名不接收邮件
		if content == "." {
			return nil
		}
		// MX 目标是主机名，不能带下划线
		if !isValidHostnameTarget(content) {
			return fmt.Errorf("invalid mail exchanger hostname")
		}
	case "TXT":
		// TXT 记录可以是任何文本
		if content == "" {
			return fmt.Errorf("content cannot be empty")
		}
	}
	return nil
}

// isValidDNSTarget 校验 CNAME/ALIAS 目标，允许末尾带点的绝对域名
func isValidDNSTarget(target string) bool {
	target = strings.TrimSuffix(target, ".")
	return len(target) <= 253 && dnsTargetRe.MatchString(target)
}

// luaCNAMEEntry 构造根域名 CNAME Flattening 的 LUA 记录。
// 目标会被拼进 Lua 代码，这里必须再校验一次：库里可能有校验加入之前写入的内容。
func luaCNAMEEntry(content string) (powerdns.RecordEntry, error) {
	// 去掉用户可能误加的引号，确保 Lua 语法正确
	target := strings.TrimSuffix(strings.Trim(content, "'\"`"), ".")
	if !isValidDNSTarget(target) {
		return powerdns.RecordEntry{}, fmt.Errorf("invalid CNAME target")
	}
	return powerdns.RecordEntry{Content: fmt.Sprintf("CNAME \";return '%s.'\"", target)}, nil
}

// isValidIPv4 校验 IPv4 字面量。值按原样使用：前后空白属于校验错误，
// 不能再 TrimSpace，否则带空白的地址会写进 PowerDNS。
// 含冒号的值（::ffff:192.0.2.1 这类 IPv4-mapped IPv6）一并拒绝，PowerDNS 会 422。
func isValidIPv4(ip string) bool {
	if strings.Contains(ip, ":") {
		return false
	}
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

// isValidIPv6 校验 IPv6 字面量（同样不 TrimSpace）。
func isValidIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

// isValidHostnameTarget 校验 NS/MX 目标：必须是合法主机名（不含下划线），
// 允许末尾带点的绝对域名。
func isValidHostnameTarget(target string) bool {
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	return len(target) <= 253 && nameserverHostnameRe.MatchString(target)
}

// buildRecordFQDN 构建 PowerDNS 所需的完整记录名
// Name="@" FullDomain="sub.example.com" → "sub.example.com"
// Name="www" FullDomain="sub.example.com" → "www.sub.example.com"
// isApexRecord 判断记录名是否为 zone apex
func isApexRecord(name string) bool {
	return name == "@" || name == ""
}

func buildRecordFQDN(name, fullDomain string) string {
	if name == "@" || name == "" {
		return fullDomain
	}
	return name + "." + fullDomain
}

// syncRecordSetToPowerDNS 同步同 name+type 的所有记录到 PowerDNS
func (h *DNSHandler) syncRecordSetToPowerDNS(record *models.DNSRecord, domain *models.Domain) {
	if domain.RootDomain == nil {
		return
	}
	zoneDomain := domain.FullDomain
	recordFQDN := buildRecordFQDN(record.Name, domain.FullDomain)

	// 查询同 domain+name+type 的所有活跃记录
	var allRecords []models.DNSRecord
	h.db.Where("domain_id = ? AND name = ? AND type = ? AND is_active = ?",
		record.DomainID, record.Name, record.Type, true).Find(&allRecords)

	// CNAME Flattening：根域名 CNAME 转为 LUA 记录推送到 PowerDNS
	pdnsType := record.Type
	entries := make([]powerdns.RecordEntry, 0, len(allRecords))
	if record.Type == "CNAME" && isApexRecord(record.Name) {
		pdnsType = "LUA"
		for _, r := range allRecords {
			entry, err := luaCNAMEEntry(r.Content)
			if err != nil {
				syncErr := err.Error()
				for i := range allRecords {
					allRecords[i].SyncError = &syncErr
					allRecords[i].SyncedToPowerDNS = false
					h.saveRecordSyncState(&allRecords[i])
				}
				h.updateDomainSyncStatus(record.DomainID)
				return
			}
			entries = append(entries, entry)
		}
	} else {
		for _, r := range allRecords {
			entries = append(entries, powerdns.RecordEntry{
				Content:  normalizePowerDNSContent(r.Type, r.Content),
				Priority: r.Priority,
			})
		}
	}

	err := h.pdns.SetRecords(zoneDomain, recordFQDN, pdnsType, entries, record.TTL)
	if err != nil {
		// 如果 zone 不存在，尝试创建
		if strings.Contains(err.Error(), "not found") ||
			strings.Contains(err.Error(), "Could not find") ||
			strings.Contains(err.Error(), "404") {
			fmt.Printf("Zone %s not found in PowerDNS, attempting to create...\n", zoneDomain)

			// 使用默认 nameservers 创建 zone
			defaultNS := []string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2}
			if createErr := h.pdns.EnsureDelegatedZone(zoneDomain, domain.RootDomain.Domain, ensureCanonicalNS(defaultNS)); createErr != nil {
				// 检查是否是因为zone已经存在（并发创建的情况）
				if !strings.Contains(createErr.Error(), "Conflict") && !strings.Contains(createErr.Error(), "already exists") {
					syncErr := fmt.Sprintf("Failed to create zone: %v", createErr)
					for i := range allRecords {
						allRecords[i].SyncError = &syncErr
						allRecords[i].SyncedToPowerDNS = false
						h.saveRecordSyncState(&allRecords[i])
					}
					h.updateDomainSyncStatus(record.DomainID)
					return
				}
				fmt.Printf("Zone %s already exists (possible race condition), retrying...\n", zoneDomain)
			} else {
				fmt.Printf("Successfully created delegated zone %s in PowerDNS\n", zoneDomain)
			}

			// 重试设置记录
			err = h.pdns.SetRecords(zoneDomain, recordFQDN, pdnsType, entries, record.TTL)
		}

		if err != nil {
			syncErr := err.Error()
			for i := range allRecords {
				allRecords[i].SyncError = &syncErr
				allRecords[i].SyncedToPowerDNS = false
				h.saveRecordSyncState(&allRecords[i])
			}
		} else {
			now := timeutil.Now()
			for i := range allRecords {
				allRecords[i].SyncError = nil
				allRecords[i].SyncedToPowerDNS = true
				allRecords[i].LastSyncedAt = &now
				h.saveRecordSyncState(&allRecords[i])
			}
		}
	} else {
		now := timeutil.Now()
		for i := range allRecords {
			allRecords[i].SyncError = nil
			allRecords[i].SyncedToPowerDNS = true
			allRecords[i].LastSyncedAt = &now
			h.saveRecordSyncState(&allRecords[i])
		}
	}

	h.updateDomainSyncStatus(record.DomainID)
}

// saveRecordSyncState 只写回同步状态列。后台同步用的是 SetRecords 之前读到的
// 快照，整行 Save 会把用户在这期间修改的 ttl / content / is_active 覆盖回旧值。
func (h *DNSHandler) saveRecordSyncState(record *models.DNSRecord) {
	h.db.Model(&models.DNSRecord{}).Where("id = ?", record.ID).
		Updates(map[string]interface{}{
			"sync_error":         record.SyncError,
			"synced_to_powerdns": record.SyncedToPowerDNS,
			"last_synced_at":     record.LastSyncedAt,
		})
}

// updateDomainSyncStatus 更新域名的 DNS 同步状态
func (h *DNSHandler) updateDomainSyncStatus(domainID uint) {
	var unsyncedCount int64
	h.db.Model(&models.DNSRecord{}).Where("domain_id = ? AND is_active = ? AND synced_to_powerdns = ?",
		domainID, true, false).Count(&unsyncedCount)

	h.db.Model(&models.Domain{}).Where("id = ?", domainID).
		Update("dns_synced", unsyncedCount == 0)
}

// deleteRecordFromPowerDNS 从 PowerDNS 删除记录（重新同步剩余记录）
func (h *DNSHandler) deleteRecordFromPowerDNS(record *models.DNSRecord, domain *models.Domain) {
	if domain.RootDomain == nil {
		return
	}
	zoneDomain := domain.FullDomain
	recordFQDN := buildRecordFQDN(record.Name, domain.FullDomain)

	// CNAME Flattening：根域名 CNAME 在 PowerDNS 中存储为 LUA 类型
	pdnsType := record.Type
	if record.Type == "CNAME" && isApexRecord(record.Name) {
		pdnsType = "LUA"
	}

	// 查询同 name+type 的剩余活跃记录
	var remaining []models.DNSRecord
	h.db.Where("domain_id = ? AND name = ? AND type = ? AND is_active = ?",
		record.DomainID, record.Name, record.Type, true).Find(&remaining)

	if len(remaining) == 0 {
		// 没有剩余记录，删除整个 RRset
		if err := h.pdns.DeleteRRset(zoneDomain, recordFQDN, pdnsType); err != nil {
			fmt.Printf("Warning: Failed to delete RRset from PowerDNS: %v\n", err)
		}
	} else {
		// 还有剩余记录，用剩余记录替换
		entries := make([]powerdns.RecordEntry, 0, len(remaining))
		if pdnsType == "LUA" {
			for _, r := range remaining {
				entry, err := luaCNAMEEntry(r.Content)
				if err != nil {
					// 剩余内容不能再写回 PowerDNS，直接清掉整个 RRset
					if err := h.pdns.DeleteRRset(zoneDomain, recordFQDN, pdnsType); err != nil {
						fmt.Printf("Warning: Failed to delete RRset from PowerDNS: %v\n", err)
					}
					h.updateDomainSyncStatus(record.DomainID)
					return
				}
				entries = append(entries, entry)
			}
		} else {
			for _, r := range remaining {
				entries = append(entries, powerdns.RecordEntry{
					Content:  normalizePowerDNSContent(r.Type, r.Content),
					Priority: r.Priority,
				})
			}
		}

		// 尝试更新记录，如果 zone 不存在则创建
		err := h.pdns.SetRecords(zoneDomain, recordFQDN, pdnsType, entries, remaining[0].TTL)
		if err != nil {
			// 检测 zone 是否不存在
			if strings.Contains(err.Error(), "not found") ||
				strings.Contains(err.Error(), "Could not find") ||
				strings.Contains(err.Error(), "404") {
				fmt.Printf("Zone %s not found during record deletion/update, attempting to create it\n", zoneDomain)

				// 创建 zone（使用默认 NS）
				defaultNS := []string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2}
				if createErr := h.pdns.EnsureDelegatedZone(zoneDomain, domain.RootDomain.Domain, ensureCanonicalNS(defaultNS)); createErr != nil {
					// 如果出现冲突错误，说明zone已被其他请求创建，这是正常的
					if !strings.Contains(createErr.Error(), "Conflict") &&
						!strings.Contains(createErr.Error(), "already exists") {
						fmt.Printf("Failed to create zone %s: %v\n", zoneDomain, createErr)
						return
					}
					fmt.Printf("Zone %s already exists (concurrent creation), proceeding with record update\n", zoneDomain)
				} else {
					fmt.Printf("Successfully created delegated zone %s\n", zoneDomain)
				}

				// 重试更新记录
				err = h.pdns.SetRecords(zoneDomain, recordFQDN, pdnsType, entries, remaining[0].TTL)
				if err != nil {
					fmt.Printf("Warning: Failed to update RRset in PowerDNS after zone creation: %v\n", err)
				}
			} else {
				fmt.Printf("Warning: Failed to update RRset in PowerDNS: %v\n", err)
			}
		}
	}

	h.updateDomainSyncStatus(record.DomainID)
}

// SyncFromPowerDNS 从 PowerDNS 同步所有 DNS 记录到数据库
func (h *DNSHandler) SyncFromPowerDNS(c *gin.Context) {
	userID, exists := middleware.GetUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	domainID := c.Param("domainId")

	// 验证域名所有权
	var domain models.Domain
	if err := h.db.Preload("RootDomain").First(&domain, domainID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Domain not found"})
		return
	}

	if domain.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		return
	}

	if domain.RootDomain == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Root domain not found"})
		return
	}

	// 检查是否使用自定义 nameservers
	if !domain.UseDefaultNameservers {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "Cannot sync DNS records for domains using custom nameservers. DNS records are managed on your custom nameserver, not in our PowerDNS system.",
			"use_custom_ns": true,
		})
		return
	}

	// 从 PowerDNS 获取 zone 信息
	zone, err := h.pdns.GetZone(domain.FullDomain)
	if err != nil {
		// 如果 zone 不存在，尝试创建
		if strings.Contains(err.Error(), "not found") ||
			strings.Contains(err.Error(), "Could not find") ||
			strings.Contains(err.Error(), "404") {
			fmt.Printf("Zone %s not found in PowerDNS, attempting to create...\n", domain.FullDomain)

			// 使用默认 nameservers 创建 zone
			defaultNS := []string{h.cfg.DNS.DefaultNS1, h.cfg.DNS.DefaultNS2}
			if createErr := h.pdns.EnsureDelegatedZone(domain.FullDomain, domain.RootDomain.Domain, ensureCanonicalNS(defaultNS)); createErr != nil {
				// 检查是否是因为zone已经存在（并发创建的情况）
				if !strings.Contains(createErr.Error(), "Conflict") && !strings.Contains(createErr.Error(), "already exists") {
					c.JSON(http.StatusInternalServerError, gin.H{
						"error": fmt.Sprintf("Failed to create zone in PowerDNS: %v", createErr),
					})
					return
				}
				fmt.Printf("Zone %s already exists (possible race condition), continuing...\n", domain.FullDomain)
			} else {
				fmt.Printf("Successfully created delegated zone %s in PowerDNS\n", domain.FullDomain)
			}

			// 重新获取 zone 信息
			zone, err = h.pdns.GetZone(domain.FullDomain)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("Failed to fetch zone after creation: %v", err),
				})
				return
			}
		} else {
			// 其他错误
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Failed to fetch zone from PowerDNS: %v", err),
			})
			return
		}
	}

	// 统计信息
	syncStats := struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
		Skipped int `json:"skipped"`
	}{}

	fullDomainWithDot := ensureTrailingDot(domain.FullDomain)

	// 遍历所有 RRsets
	for _, rrset := range zone.RRsets {
		// 跳过 SOA 和根域名的 NS 记录
		if rrset.Type == "SOA" {
			continue
		}
		if rrset.Type == "NS" && rrset.Name == fullDomainWithDot {
			continue
		}

		// 只处理属于当前域名的记录
		if rrset.Name != fullDomainWithDot && !strings.HasSuffix(rrset.Name, "."+fullDomainWithDot) {
			continue
		}

		// 解析记录名称（将 FQDN 转换为本地名称）
		recordName := extractRecordName(rrset.Name, domain.FullDomain)

		// CNAME Flattening 反向映射：LUA CNAME 记录还原为 CNAME 类型
		rrsetType := rrset.Type
		var luaCNAMEContent string
		if rrset.Type == "LUA" && isApexRecord(recordName) {
			for _, r := range rrset.Records {
				if strings.HasPrefix(r.Content, "CNAME ") {
					// 格式: CNAME ";return 'target.'"
					// 提取单引号内的目标
					s := strings.TrimPrefix(r.Content, "CNAME ")
					start := strings.Index(s, "'")
					end := strings.LastIndex(s, "'")
					if start >= 0 && end > start {
						luaCNAMEContent = strings.TrimSuffix(s[start+1:end], ".")
						rrsetType = "CNAME"
					}
				}
			}
		}

		// 处理每条记录
		for _, record := range rrset.Records {
			if record.Disabled {
				continue // 跳过已禁用的记录
			}

			// 解析记录内容和优先级
			// 对于 LUA CNAME 记录，使用反向映射后的内容
			var content string
			var priority *int
			if luaCNAMEContent != "" {
				content = luaCNAMEContent
				// LUA CNAME 不需要再处理 priority
			} else {
				content, priority = parseRecordContent(rrset.Type, record.Content)
			}

			// 检查是否已存在相同记录
			var existingRecord models.DNSRecord
			err := h.db.Where("domain_id = ? AND name = ? AND type = ? AND content = ?",
				domain.ID, recordName, rrsetType, content).First(&existingRecord).Error

			now := timeutil.Now()
			if err == gorm.ErrRecordNotFound {
				// 创建新记录
				newRecord := &models.DNSRecord{
					DomainID:         domain.ID,
					Name:             recordName,
					Type:             rrsetType,
					Content:          content,
					TTL:              rrset.TTL,
					Priority:         priority,
					IsActive:         true,
					SyncedToPowerDNS: true,
					LastSyncedAt:     &now,
				}
				if err := h.db.Create(newRecord).Error; err != nil {
					fmt.Printf("Warning: Failed to create DNS record: %v\n", err)
					syncStats.Skipped++
				} else {
					syncStats.Created++
				}
			} else if err == nil {
				// 更新现有记录
				existingRecord.TTL = rrset.TTL
				existingRecord.Priority = priority
				existingRecord.IsActive = true
				existingRecord.SyncedToPowerDNS = true
				existingRecord.LastSyncedAt = &now
				existingRecord.SyncError = nil

				if err := h.db.Save(&existingRecord).Error; err != nil {
					fmt.Printf("Warning: Failed to update DNS record: %v\n", err)
					syncStats.Skipped++
				} else {
					syncStats.Updated++
				}
			} else {
				fmt.Printf("Warning: Failed to query DNS record: %v\n", err)
				syncStats.Skipped++
			}
		}
	}

	// 更新域名同步状态
	h.updateDomainSyncStatus(domain.ID)

	c.JSON(http.StatusOK, gin.H{
		"message": "DNS records synced from PowerDNS successfully",
		"stats":   syncStats,
	})
}

// extractRecordName 从 FQDN 提取记录名称
// "sub.example.com." + "example.com" -> "sub"
// "example.com." + "example.com" -> "@"
func extractRecordName(fqdn, fullDomain string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	fullDomain = strings.TrimSuffix(fullDomain, ".")

	if fqdn == fullDomain {
		return "@"
	}

	if strings.HasSuffix(fqdn, "."+fullDomain) {
		return strings.TrimSuffix(fqdn, "."+fullDomain)
	}

	return fqdn
}

// parseRecordContent 解析记录内容，提取优先级（如果有）
// 从 PowerDNS 读取时去除 TXT/CAA 的引号，还原为用户友好格式
func parseRecordContent(recordType, content string) (string, *int) {
	content = strings.TrimSuffix(content, ".")

	// MX 记录格式: "10 mail.example.com."
	if recordType == "MX" {
		parts := strings.Fields(content)
		if len(parts) >= 2 {
			if priority, err := strconv.Atoi(parts[0]); err == nil {
				return strings.TrimSuffix(parts[1], "."), &priority
			}
		}
	}

	// TXT/SPF: 去除 PowerDNS 的引号，支持多段 "part1" "part2" -> "part1 part2"
	if recordType == "TXT" || recordType == "SPF" {
		// 合并多段引用: "part1" "part2" -> part1 part2
		content = strings.ReplaceAll(content, "\" \"", " ")
		content = strings.Trim(content, "\"")
		content = strings.ReplaceAll(content, "\\\"", "\"")
	}

	// CAA: 去除 value 段的引号
	// PowerDNS 返回: 0 issue "letsencrypt.org" -> 存储: 0 issue letsencrypt.org
	if recordType == "CAA" {
		parts := strings.Fields(content)
		if len(parts) >= 3 {
			value := strings.Join(parts[2:], " ")
			value = strings.Trim(value, "\"")
			value = strings.ReplaceAll(value, "\\\"", "\"")
			content = parts[0] + " " + parts[1] + " " + value
		}
	}

	return content, nil
}

// ensureTrailingDot 确保字符串以点结尾（用于 PowerDNS FQDN）
func ensureTrailingDot(s string) string {
	if len(s) == 0 {
		return s
	}
	if s[len(s)-1] != '.' {
		return s + "."
	}
	return s
}
