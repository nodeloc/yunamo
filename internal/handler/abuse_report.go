package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"opendomain/internal/config"
	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/internal/services"
	"opendomain/pkg/logger"
	"opendomain/pkg/timeutil"
)

const (
	abuseReportRateLimit        = 5
	abuseReportRateWindow       = time.Hour
	abuseReportGlobalLimit      = 200
	abuseReportMaxBodyBytes     = 64 << 10
	abuseReportDetailsMinLength = 10
	abuseReportDetailsMaxLength = 5000
	abuseReportURLMaxLength     = 2048
	abuseReportEmailMaxLength   = 254
	abuseReportNoteMaxLength    = 5000
)

type AbuseReportHandler struct {
	db     *gorm.DB
	rdb    *redis.Client
	cfg    *config.Config
	mailer *services.Mailer
}

func NewAbuseReportHandler(db *gorm.DB, rdb *redis.Client, cfg *config.Config, mailer *services.Mailer) *AbuseReportHandler {
	return &AbuseReportHandler{db: db, rdb: rdb, cfg: cfg, mailer: mailer}
}

// tr translates key and falls back to the given English text when the
// locale files are not available (the translator returns the key itself).
func tr(c *gin.Context, key, fallback string) string {
	if s := middleware.T(c, key); s != "" && s != key {
		return s
	}
	return fallback
}

func isValidAbuseCategory(category string) bool {
	for _, v := range models.AbuseReportCategories {
		if v == category {
			return true
		}
	}
	return false
}

func isValidAbuseStatus(status string) bool {
	for _, v := range models.AbuseReportStatuses {
		if v == status {
			return true
		}
	}
	return false
}

func isClosedAbuseStatus(status string) bool {
	return status == models.AbuseReportStatusResolved || status == models.AbuseReportStatusDismissed
}

// normalizeReportedHostname lowercases and trims the reported name. People
// often paste a full URL, so a scheme/path is tolerated and the host kept.
func normalizeReportedHostname(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", false
		}
		s = u.Hostname()
	} else if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || !nameserverHostnameRe.MatchString(s) {
		return "", false
	}
	return s, true
}

func isValidReporterEmail(email string) bool {
	if len(email) > abuseReportEmailMaxLength {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return false
	}
	at := strings.LastIndex(email, "@")
	return at > 0 && strings.Contains(email[at+1:], ".")
}

// hostnameCandidates returns the name and each parent name with at least two
// labels, so a report for "www.foo.loc.cc" still matches the registered
// "foo.loc.cc".
func hostnameCandidates(hostname string) []string {
	labels := strings.Split(hostname, ".")
	out := make([]string, 0, len(labels))
	for i := 0; i+2 <= len(labels); i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

func (h *AbuseReportHandler) matchDomain(hostname string) *models.Domain {
	var domains []models.Domain
	if err := h.db.Select("id", "full_domain", "status").
		Where("full_domain IN ?", hostnameCandidates(hostname)).
		Find(&domains).Error; err != nil || len(domains) == 0 {
		return nil
	}
	best := &domains[0]
	for i := range domains {
		if len(domains[i].FullDomain) > len(best.FullDomain) {
			best = &domains[i]
		}
	}
	return best
}

// allowReport enforces the per-IP submission limit plus a site-wide cap.
// The per-IP key relies on forwarded headers that a client can forge, so the
// global cap is what bounds the table size if those headers are spoofed.
// Redis is the primary counter; if it is unavailable the database is used.
func (h *AbuseReportHandler) allowReport(ctx context.Context, ip string) bool {
	if h.rdb != nil {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		global, gerr := h.incrWindow(rctx, "abuse_report:rate:global")
		perIP, err := h.incrWindow(rctx, "abuse_report:rate:"+ip)
		if err == nil && gerr == nil {
			return perIP <= abuseReportRateLimit && global <= abuseReportGlobalLimit
		}
		logger.Warnf("abuse report rate limit: redis unavailable, falling back to database: %v %v", err, gerr)
	}

	since := timeutil.Now().Add(-abuseReportRateWindow)
	var count, total int64
	if err := h.db.Model(&models.AbuseReport{}).
		Where("reporter_ip = ? AND created_at > ?", ip, since).
		Count(&count).Error; err != nil {
		logger.Errorf("abuse report rate limit: database count failed: %v", err)
		return true
	}
	if err := h.db.Model(&models.AbuseReport{}).
		Where("created_at > ?", since).
		Count(&total).Error; err != nil {
		logger.Errorf("abuse report rate limit: database count failed: %v", err)
		return true
	}
	return count < abuseReportRateLimit && total < abuseReportGlobalLimit
}

func (h *AbuseReportHandler) incrWindow(ctx context.Context, key string) (int64, error) {
	return incrRateWindow(ctx, h.rdb, key, abuseReportRateWindow)
}

// reporterIP returns the client address used for rate limiting. It relies on
// gin's trusted-proxy handling (see router.Setup), so headers sent by clients
// that are not a trusted proxy are ignored.
func reporterIP(c *gin.Context) string {
	ip := c.ClientIP()
	if len(ip) > 64 {
		ip = ip[:64]
	}
	return ip
}

// CreateAbuseReport 公开：提交滥用举报
func (h *AbuseReportHandler) CreateAbuseReport(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, abuseReportMaxBodyBytes)

	var req models.AbuseReportCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "error.validation", "Validation failed")})
		return
	}

	hostname, ok := normalizeReportedHostname(req.Subdomain)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "abuse.invalid_subdomain", "Enter the full domain name, for example foo.example.com")})
		return
	}

	category := strings.ToLower(strings.TrimSpace(req.Category))
	if !isValidAbuseCategory(category) {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "abuse.invalid_category", "Choose a valid report category")})
		return
	}

	details := strings.TrimSpace(stripNUL(req.Details))
	if n := utf8.RuneCountInString(details); n < abuseReportDetailsMinLength || n > abuseReportDetailsMaxLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "abuse.invalid_details", "Details must be between 10 and 5000 characters")})
		return
	}

	reportURL := strings.TrimSpace(stripNUL(req.URL))
	if len(reportURL) > abuseReportURLMaxLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "abuse.invalid_url", "The URL is too long (2048 characters max)")})
		return
	}

	email := strings.TrimSpace(req.ReporterEmail)
	if email != "" && !isValidReporterEmail(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "validation.email_invalid", "Invalid email format")})
		return
	}

	ip := reporterIP(c)
	if !h.allowReport(c.Request.Context(), ip) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": tr(c, "abuse.rate_limited", "Too many reports from your network. Please try again later.")})
		return
	}

	userAgent := c.Request.UserAgent()
	if len(userAgent) > 512 {
		userAgent = userAgent[:512]
	}

	report := &models.AbuseReport{
		Subdomain:     hostname,
		Category:      category,
		URL:           reportURL,
		Details:       details,
		ReporterEmail: email,
		ReporterIP:    ip,
		UserAgent:     stripNUL(strings.ToValidUTF8(userAgent, "")),
		Status:        models.AbuseReportStatusOpen,
		Locale:        services.NormalizeLocale(middleware.GetLocale(c)),
	}
	domainStatus := ""
	if domain := h.matchDomain(hostname); domain != nil {
		id := domain.ID
		report.DomainID = &id
		domainStatus = domain.Status
	}

	if err := h.db.Create(report).Error; err != nil {
		logger.Errorf("failed to create abuse report: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "error.internal_server", "Internal server error")})
		return
	}

	h.notifyAdmins(*report, domainStatus)

	c.JSON(http.StatusCreated, gin.H{
		"id":      report.ID,
		"message": tr(c, "abuse.report_received", "Thanks, your report has been received"),
	})
}

// stripNUL removes NUL characters, which PostgreSQL rejects in text columns.
func stripNUL(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func (h *AbuseReportHandler) domainStatuses(reports []models.AbuseReport) map[uint]string {
	ids := make([]uint, 0, len(reports))
	seen := make(map[uint]bool)
	for _, r := range reports {
		if r.DomainID != nil && !seen[*r.DomainID] {
			seen[*r.DomainID] = true
			ids = append(ids, *r.DomainID)
		}
	}
	out := make(map[uint]string, len(ids))
	if len(ids) == 0 {
		return out
	}
	var domains []models.Domain
	if err := h.db.Unscoped().Select("id", "status", "deleted_at").Where("id IN ?", ids).Find(&domains).Error; err != nil {
		logger.Warnf("failed to load domain statuses for abuse reports: %v", err)
		return out
	}
	for _, d := range domains {
		if d.DeletedAt.Valid {
			out[d.ID] = "deleted"
		} else {
			out[d.ID] = d.Status
		}
	}
	return out
}

func (h *AbuseReportHandler) toResponses(reports []models.AbuseReport) []*models.AbuseReportResponse {
	statuses := h.domainStatuses(reports)
	out := make([]*models.AbuseReportResponse, len(reports))
	for i := range reports {
		var ds *string
		if reports[i].DomainID != nil {
			if s, ok := statuses[*reports[i].DomainID]; ok {
				ds = &s
			}
		}
		out[i] = reports[i].ToResponse(ds)
	}
	return out
}

// ListAbuseReports 管理员：举报列表
func (h *AbuseReportHandler) ListAbuseReports(c *gin.Context) {
	status := strings.TrimSpace(c.Query("status"))
	search := strings.TrimSpace(c.Query("search"))
	page := 1
	pageSize := 20
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(c.Query("page_size")); err == nil && ps > 0 && ps <= 100 {
		pageSize = ps
	}
	if status != "" && !isValidAbuseStatus(status) {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "abuse.invalid_status", "Invalid status")})
		return
	}

	base := func() *gorm.DB {
		q := h.db.Model(&models.AbuseReport{})
		if search != "" {
			like := "%" + escapeLike(search) + "%"
			q = q.Where("subdomain ILIKE ? OR details ILIKE ? OR reporter_email ILIKE ?", like, like, like)
		}
		return q
	}

	counts := gin.H{}
	for _, s := range models.AbuseReportStatuses {
		counts[s] = int64(0)
	}
	var grouped []struct {
		Status string
		Count  int64
	}
	if err := base().Select("status, COUNT(*) AS count").Group("status").Scan(&grouped).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "abuse.fetch_failed", "Failed to fetch abuse reports")})
		return
	}
	for _, g := range grouped {
		if _, ok := counts[g.Status]; ok {
			counts[g.Status] = g.Count
		}
	}

	query := base()
	if status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "abuse.fetch_failed", "Failed to fetch abuse reports")})
		return
	}

	var reports []models.AbuseReport
	if err := query.Order("created_at DESC, id DESC").
		Offset((page - 1) * pageSize).Limit(pageSize).
		Find(&reports).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "abuse.fetch_failed", "Failed to fetch abuse reports")})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"reports":   h.toResponses(reports),
		"total":     total,
		"page":      page,
		"page_size": pageSize,
		"counts":    counts,
	})
}

func (h *AbuseReportHandler) findReport(c *gin.Context) (*models.AbuseReport, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "error.invalid_parameter", "Invalid parameter")})
		return nil, false
	}
	var report models.AbuseReport
	if err := h.db.First(&report, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": tr(c, "abuse.not_found", "Abuse report not found")})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "error.internal_server", "Internal server error")})
		}
		return nil, false
	}
	return &report, true
}

// UpdateAbuseReport 管理员：更新举报状态/备注
func (h *AbuseReportHandler) UpdateAbuseReport(c *gin.Context) {
	report, ok := h.findReport(c)
	if !ok {
		return
	}
	prevStatus := report.Status

	var req models.AbuseReportUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "error.validation", "Validation failed")})
		return
	}

	if req.Status != nil {
		newStatus := strings.TrimSpace(*req.Status)
		if !isValidAbuseStatus(newStatus) {
			c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "abuse.invalid_status", "Invalid status")})
			return
		}
		if isClosedAbuseStatus(newStatus) {
			if !isClosedAbuseStatus(report.Status) || report.ResolvedAt == nil {
				now := timeutil.Now()
				report.ResolvedAt = &now
			}
		} else {
			report.ResolvedAt = nil
		}
		report.Status = newStatus
	}

	if req.AdminNote != nil {
		note := strings.TrimSpace(stripNUL(*req.AdminNote))
		if utf8.RuneCountInString(note) > abuseReportNoteMaxLength {
			c.JSON(http.StatusBadRequest, gin.H{"error": tr(c, "abuse.note_too_long", fmt.Sprintf("Admin note must be at most %d characters", abuseReportNoteMaxLength))})
			return
		}
		report.AdminNote = note
	}

	if err := h.db.Save(report).Error; err != nil {
		logger.Errorf("failed to update abuse report %d: %v", report.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "abuse.update_failed", "Failed to update abuse report")})
		return
	}

	if !isClosedAbuseStatus(prevStatus) && isClosedAbuseStatus(report.Status) && report.ReporterEmail != "" {
		h.notifyReporter(*report)
	}

	c.JSON(http.StatusOK, gin.H{"report": h.toResponses([]models.AbuseReport{*report})[0]})
}

// notifyAdmins emails every active admin about a new report. The admin
// lookup runs in the background with the sending.
func (h *AbuseReportHandler) notifyAdmins(report models.AbuseReport, domainStatus string) {
	h.mailer.Go("abuse-report-alert", func() {
		var emails []string
		if err := h.db.Model(&models.User{}).
			Where("is_admin = ? AND status = ? AND email <> ?", true, "active", "").
			Pluck("email", &emails).Error; err != nil {
			logger.Errorf("abuse report %d: failed to load admin emails: %v", report.ID, err)
			return
		}
		alert := services.AbuseAlert{
			ID:            report.ID,
			Category:      report.Category,
			Subdomain:     report.Subdomain,
			URL:           report.URL,
			DomainStatus:  domainStatus,
			Details:       report.Details,
			ReporterEmail: report.ReporterEmail,
			CreatedAt:     report.CreatedAt,
			AdminURL:      strings.TrimRight(h.cfg.FrontendURL, "/") + "/admin/abuse-reports",
		}
		for _, to := range emails {
			m, err := services.AbuseAlertMail(h.cfg.SiteName, to, alert)
			if err != nil {
				logger.Errorf("abuse report %d: failed to build admin alert: %v", report.ID, err)
				continue
			}
			h.mailer.SendAsync(m)
		}
	})
}

func (h *AbuseReportHandler) notifyReporter(report models.AbuseReport) {
	resolved := report.Status == models.AbuseReportStatusResolved
	m, err := services.AbuseOutcomeMail(report.Locale, h.cfg.SiteName, report.ReporterEmail, report.ID, report.Subdomain, resolved)
	if err != nil {
		logger.Errorf("abuse report %d: failed to build reporter email: %v", report.ID, err)
		return
	}
	h.mailer.SendAsync(m)
}

// DeleteAbuseReport 管理员：删除举报
func (h *AbuseReportHandler) DeleteAbuseReport(c *gin.Context) {
	report, ok := h.findReport(c)
	if !ok {
		return
	}
	if err := h.db.Delete(&models.AbuseReport{}, report.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": tr(c, "abuse.delete_failed", "Failed to delete abuse report")})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": tr(c, "abuse.deleted", "Abuse report deleted")})
}
