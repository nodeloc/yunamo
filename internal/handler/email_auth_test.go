package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"opendomain/internal/config"
	"opendomain/internal/middleware"
	"opendomain/internal/models"
	"opendomain/internal/services"
	"opendomain/pkg/logger"
	"opendomain/pkg/timeutil"
)

func TestMain(m *testing.M) {
	logger.Init("error")
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

type fakeSender struct {
	mu   sync.Mutex
	sent []*services.Mail
}

func (f *fakeSender) Send(_ context.Context, m *services.Mail) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeSender) all() []*services.Mail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*services.Mail(nil), f.sent...)
}

var testDBSeq int64

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:emailtest%d?mode=memory&cache=shared", atomic.AddInt64(&testDBSeq, 1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	if err := db.AutoMigrate(&models.User{}, &models.EmailToken{}, &models.AbuseReport{}, &models.Invitation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func testConfig() *config.Config {
	return &config.Config{SiteName: "Yunamo", FrontendURL: "https://yunamo.com/"}
}

func syncMailer() (*services.Mailer, *fakeSender) {
	fake := &fakeSender{}
	return &services.Mailer{Sender: fake, Run: func(_ string, fn func()) { fn() }}, fake
}

var userSeq int64

func createTestUser(t *testing.T, db *gorm.DB, email string, verified bool, mutate ...func(*models.User)) *models.User {
	t.Helper()
	n := atomic.AddInt64(&userSeq, 1)
	u := &models.User{
		Username:      fmt.Sprintf("user%d", n),
		Email:         email,
		EmailVerified: verified,
		PasswordHash:  "x",
		InviteCode:    fmt.Sprintf("inv%d", n),
		UserLevel:     "normal",
		DomainQuota:   2,
		Status:        "active",
	}
	for _, m := range mutate {
		m(u)
	}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	// GORM skips zero-value bools that have a default tag on insert.
	if err := db.Model(u).Update("email_verified", verified).Error; err != nil {
		t.Fatalf("set email_verified: %v", err)
	}
	return u
}

func withUser(id uint) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", id)
		c.Next()
	}
}

func doJSON(r http.Handler, method, path string, body interface{}, headers ...string) (int, map[string]interface{}) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

var tokenInLink = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)

func tokenFromMail(t *testing.T, m *services.Mail) string {
	t.Helper()
	match := tokenInLink.FindStringSubmatch(m.Text)
	if match == nil {
		t.Fatalf("no token link in mail text: %q", m.Text)
	}
	return match[1]
}

func newUserRouter(h *UserHandler, userID uint) *gin.Engine {
	r := gin.New()
	r.Use(middleware.I18nMiddleware())
	r.POST("/api/auth/register", h.Register)
	r.POST("/api/auth/forgot-password", h.ForgotPassword)
	r.POST("/api/auth/reset-password", h.ResetPassword)
	r.POST("/api/auth/verify-email", h.VerifyEmail)
	r.POST("/api/user/resend-verification", withUser(userID), h.ResendVerification)
	return r
}

func TestEmailTokenGenerationAndHashing(t *testing.T) {
	raw, hash, err := generateEmailToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 43 || strings.ContainsAny(raw, "+/=") {
		t.Fatalf("raw token %q is not 32 bytes of unpadded base64url", raw)
	}
	if len(hash) != 64 || hash != hashEmailToken(raw) || hash == raw {
		t.Fatalf("hash %q does not match sha256 hex of raw token", hash)
	}
	raw2, _, _ := generateEmailToken()
	if raw2 == raw {
		t.Fatal("two generated tokens are identical")
	}
}

func TestEmailTokenSingleUseExpiryAndRotation(t *testing.T) {
	db := newTestDB(t)
	u := createTestUser(t, db, "tok@example.com", false)
	now := timeutil.Now()

	raw, err := issueEmailToken(db, u.ID, models.EmailTokenPurposeVerifyEmail, u.Email, verifyEmailTokenTTL, now)
	if err != nil {
		t.Fatal(err)
	}
	var stored models.EmailToken
	db.Where("user_id = ?", u.ID).First(&stored)
	if stored.TokenHash != hashEmailToken(raw) || stored.TokenHash == raw {
		t.Fatal("raw token must not be stored, only its hash")
	}
	if !stored.ExpiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("verify token expires at %v, want +24h", stored.ExpiresAt)
	}

	if _, err := consumeEmailToken(db, raw, models.EmailTokenPurposeResetPassword, now); err != errInvalidEmailToken {
		t.Fatalf("token redeemed for the wrong purpose: %v", err)
	}
	if _, err := consumeEmailToken(db, raw, models.EmailTokenPurposeVerifyEmail, now); err != nil {
		t.Fatalf("first use failed: %v", err)
	}
	if _, err := consumeEmailToken(db, raw, models.EmailTokenPurposeVerifyEmail, now); err != errInvalidEmailToken {
		t.Fatalf("second use = %v, want errInvalidEmailToken", err)
	}

	expired, _ := issueEmailToken(db, u.ID, models.EmailTokenPurposeResetPassword, u.Email, resetPasswordTokenTTL, now.Add(-2*time.Hour))
	if _, err := consumeEmailToken(db, expired, models.EmailTokenPurposeResetPassword, now); err != errInvalidEmailToken {
		t.Fatalf("expired token = %v, want errInvalidEmailToken", err)
	}

	older, _ := issueEmailToken(db, u.ID, models.EmailTokenPurposeResetPassword, u.Email, resetPasswordTokenTTL, now)
	newer, _ := issueEmailToken(db, u.ID, models.EmailTokenPurposeResetPassword, u.Email, resetPasswordTokenTTL, now)
	if _, err := consumeEmailToken(db, older, models.EmailTokenPurposeResetPassword, now); err != errInvalidEmailToken {
		t.Fatalf("older token still valid after a new one was issued: %v", err)
	}
	if _, err := consumeEmailToken(db, newer, models.EmailTokenPurposeResetPassword, now); err != nil {
		t.Fatalf("newest token rejected: %v", err)
	}
}

func TestForgotPasswordDoesNotRevealAccounts(t *testing.T) {
	db := newTestDB(t)
	mailer, fake := syncMailer()
	h := NewUserHandler(db, nil, testConfig(), mailer)
	r := newUserRouter(h, 0)
	createTestUser(t, db, "Known@Example.com", true)
	createTestUser(t, db, "banned@example.com", true, func(u *models.User) { u.Status = "banned" })

	codeKnown, bodyKnown := doJSON(r, "POST", "/api/auth/forgot-password", gin.H{"email": " known@example.com "}, "Accept-Language", "en-US")
	codeUnknown, bodyUnknown := doJSON(r, "POST", "/api/auth/forgot-password", gin.H{"email": "nobody@example.com"}, "Accept-Language", "en-US")
	if codeKnown != http.StatusOK || codeUnknown != http.StatusOK {
		t.Fatalf("status known=%d unknown=%d, want 200", codeKnown, codeUnknown)
	}
	if fmt.Sprint(bodyKnown) != fmt.Sprint(bodyUnknown) {
		t.Fatalf("responses differ: %v vs %v", bodyKnown, bodyUnknown)
	}

	sent := fake.all()
	if len(sent) != 1 || sent[0].To != "Known@Example.com" {
		t.Fatalf("expected one reset mail to the known account, got %+v", sent)
	}
	if !strings.Contains(sent[0].Text, "https://yunamo.com/reset-password?token=") || !strings.Contains(sent[0].Subject, "Reset your password") {
		t.Fatalf("unexpected reset mail: %q %q", sent[0].Subject, sent[0].Text)
	}

	if code, _ := doJSON(r, "POST", "/api/auth/forgot-password", gin.H{"email": "banned@example.com"}); code != http.StatusOK {
		t.Fatalf("banned account status = %d, want 200", code)
	}
	if len(fake.all()) != 1 {
		t.Fatal("reset mail was sent to a banned account")
	}

	if code, body := doJSON(r, "POST", "/api/auth/forgot-password", gin.H{"email": "not-an-email"}); code != http.StatusBadRequest || body["error"] == nil {
		t.Fatalf("invalid email = %d %v, want 400 with error", code, body)
	}
}

func TestResetPasswordFlow(t *testing.T) {
	db := newTestDB(t)
	mailer, fake := syncMailer()
	h := NewUserHandler(db, nil, testConfig(), mailer)
	r := newUserRouter(h, 0)
	u := createTestUser(t, db, "reset@example.com", false)

	doJSON(r, "POST", "/api/auth/forgot-password", gin.H{"email": "reset@example.com"})
	doJSON(r, "POST", "/api/auth/forgot-password", gin.H{"email": "reset@example.com"})
	sent := fake.all()
	if len(sent) != 2 {
		t.Fatalf("expected two reset mails, got %d", len(sent))
	}
	stale, token := tokenFromMail(t, sent[0]), tokenFromMail(t, sent[1])

	if code, body := doJSON(r, "POST", "/api/auth/reset-password", gin.H{"token": token, "password": "123"}); code != http.StatusBadRequest || body["code"] != nil {
		t.Fatalf("short password = %d %v, want plain 400", code, body)
	}
	if code, body := doJSON(r, "POST", "/api/auth/reset-password", gin.H{"token": stale, "password": "newpassword"}); code != http.StatusBadRequest || body["code"] != "invalid_token" {
		t.Fatalf("superseded token = %d %v, want invalid_token", code, body)
	}
	if code, body := doJSON(r, "POST", "/api/auth/reset-password", gin.H{"token": "bogus", "password": "newpassword"}); code != http.StatusBadRequest || body["code"] != "invalid_token" {
		t.Fatalf("bogus token = %d %v, want invalid_token", code, body)
	}

	code, body := doJSON(r, "POST", "/api/auth/reset-password", gin.H{"token": token, "password": "newpassword"})
	if code != http.StatusOK || body["message"] == nil {
		t.Fatalf("reset = %d %v, want 200", code, body)
	}
	var got models.User
	db.First(&got, u.ID)
	if bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte("newpassword")) != nil {
		t.Fatal("password hash was not updated")
	}
	if !got.EmailVerified {
		t.Fatal("reset should mark the email as verified")
	}

	if code, body := doJSON(r, "POST", "/api/auth/reset-password", gin.H{"token": token, "password": "another1"}); code != http.StatusBadRequest || body["code"] != "invalid_token" {
		t.Fatalf("reused token = %d %v, want invalid_token", code, body)
	}
}

func TestVerifyEmailFlow(t *testing.T) {
	db := newTestDB(t)
	mailer, fake := syncMailer()
	h := NewUserHandler(db, nil, testConfig(), mailer)
	r := newUserRouter(h, 0)

	code, body := doJSON(r, "POST", "/api/auth/register", gin.H{"username": "newbie", "email": "newbie@example.com", "password": "secret1"})
	if code != http.StatusOK || body["email_verification_sent"] != true || body["user"] == nil {
		t.Fatalf("register = %d %v", code, body)
	}
	if user, _ := body["user"].(map[string]interface{}); user["email_verified"] != false {
		t.Fatalf("new user email_verified = %v, want false", user["email_verified"])
	}
	sent := fake.all()
	if len(sent) != 1 || sent[0].To != "newbie@example.com" || !strings.Contains(sent[0].Text, "https://yunamo.com/verify-email?token=") {
		t.Fatalf("expected verification mail, got %+v", sent)
	}
	if !strings.Contains(sent[0].Subject, "验证") {
		t.Fatalf("default locale should be zh-CN, subject %q", sent[0].Subject)
	}

	code, body = doJSON(r, "POST", "/api/auth/verify-email", gin.H{"token": tokenFromMail(t, sent[0])})
	if code != http.StatusOK || body["email"] != "newbie@example.com" {
		t.Fatalf("verify = %d %v", code, body)
	}
	var u models.User
	db.Where("email = ?", "newbie@example.com").First(&u)
	if !u.EmailVerified {
		t.Fatal("user was not marked verified")
	}
}

func TestVerifyEmailRejectsChangedEmail(t *testing.T) {
	db := newTestDB(t)
	mailer, _ := syncMailer()
	h := NewUserHandler(db, nil, testConfig(), mailer)
	r := newUserRouter(h, 0)
	u := createTestUser(t, db, "old@example.com", false)

	raw, err := issueEmailToken(db, u.ID, models.EmailTokenPurposeVerifyEmail, u.Email, verifyEmailTokenTTL, timeutil.Now())
	if err != nil {
		t.Fatal(err)
	}
	db.Model(u).Update("email", "new@example.com")

	code, body := doJSON(r, "POST", "/api/auth/verify-email", gin.H{"token": raw})
	if code != http.StatusBadRequest || body["code"] != "invalid_token" {
		t.Fatalf("verify after email change = %d %v, want invalid_token", code, body)
	}
	var got models.User
	db.First(&got, u.ID)
	if got.EmailVerified {
		t.Fatal("changed email must not be marked verified")
	}
}

func TestResendVerification(t *testing.T) {
	db := newTestDB(t)
	mailer, fake := syncMailer()
	h := NewUserHandler(db, nil, testConfig(), mailer)
	verified := createTestUser(t, db, "done@example.com", true)
	pending := createTestUser(t, db, "pending@example.com", false)

	if code, body := doJSON(newUserRouter(h, verified.ID), "POST", "/api/user/resend-verification", nil); code != http.StatusBadRequest || body["code"] != "already_verified" {
		t.Fatalf("verified user = %d %v, want already_verified", code, body)
	}

	r := newUserRouter(h, pending.ID)
	if code, _ := doJSON(r, "POST", "/api/user/resend-verification", nil, "Accept-Language", "en-US,en;q=0.9"); code != http.StatusOK {
		t.Fatalf("first resend = %d, want 200", code)
	}
	if sent := fake.all(); len(sent) != 1 || !strings.Contains(sent[0].Subject, "Verify your email") {
		t.Fatalf("expected one English verification mail, got %+v", sent)
	}
	code, body := doJSON(r, "POST", "/api/user/resend-verification", nil)
	retry, _ := body["retry_after"].(float64)
	if code != http.StatusTooManyRequests || body["code"] != "rate_limited" || retry < 1 || retry > 60 {
		t.Fatalf("immediate resend = %d %v, want 429 with retry_after in (0,60]", code, body)
	}

	now := timeutil.Now()
	db.Where("user_id = ?", pending.ID).Delete(&models.EmailToken{})
	for i := 0; i < resendVerificationHourlyLimit; i++ {
		db.Create(&models.EmailToken{
			UserID: pending.ID, Purpose: models.EmailTokenPurposeVerifyEmail, TokenHash: fmt.Sprintf("%064d", i),
			Email: pending.Email, ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Duration(50-i*5) * time.Minute),
		})
	}
	code, body = doJSON(r, "POST", "/api/user/resend-verification", nil)
	retry, _ = body["retry_after"].(float64)
	if code != http.StatusTooManyRequests || retry < 9*60 || retry > 10*60+1 {
		t.Fatalf("hourly limit = %d %v, want 429 with ~600s retry_after", code, body)
	}
}

func TestEmailNotVerifiedGate(t *testing.T) {
	db := newTestDB(t)
	cfg := testConfig()
	u := createTestUser(t, db, "gate@example.com", false)
	domainHandler := &DomainHandler{db: db, cfg: cfg}
	orderHandler := NewOrderHandler(db, cfg)

	r := gin.New()
	r.Use(middleware.I18nMiddleware(), withUser(u.ID))
	r.POST("/api/domains", domainHandler.RegisterDomain)
	r.POST("/api/orders", orderHandler.CreateOrder)

	for _, path := range []string{"/api/domains", "/api/orders"} {
		code, body := doJSON(r, "POST", path, gin.H{"subdomain": "foo", "root_domain_id": 1})
		if code != http.StatusForbidden || body["code"] != "email_not_verified" || body["error"] == nil {
			t.Fatalf("%s = %d %v, want 403 email_not_verified", path, code, body)
		}
	}
}

func newAbuseRouter(h *AbuseReportHandler) *gin.Engine {
	r := gin.New()
	r.Use(middleware.I18nMiddleware())
	r.POST("/api/public/abuse-reports", h.CreateAbuseReport)
	r.PUT("/api/admin/abuse-reports/:id", h.UpdateAbuseReport)
	return r
}

func TestAbuseReportOutcomeEmail(t *testing.T) {
	db := newTestDB(t)
	mailer, fake := syncMailer()
	h := NewAbuseReportHandler(db, nil, testConfig(), mailer)
	r := newAbuseRouter(h)

	report := &models.AbuseReport{
		Subdomain: "bad.loc.cc", Category: "phishing", Details: "phishing page here",
		ReporterEmail: "reporter@example.com", Status: models.AbuseReportStatusOpen, Locale: "en-US",
	}
	db.Create(report)
	path := fmt.Sprintf("/api/admin/abuse-reports/%d", report.ID)
	put := func(body gin.H) {
		t.Helper()
		if code, resp := doJSON(r, "PUT", path, body); code != http.StatusOK {
			t.Fatalf("PUT %v = %d %v", body, code, resp)
		}
	}

	put(gin.H{"status": "reviewing", "admin_note": "looking"})
	if n := len(fake.all()); n != 0 {
		t.Fatalf("non-closing update sent %d mails", n)
	}

	put(gin.H{"status": "resolved", "admin_note": "SECRET-ADMIN-NOTE"})
	put(gin.H{"status": "resolved"})
	put(gin.H{"status": "dismissed"})
	sent := fake.all()
	if len(sent) != 1 {
		t.Fatalf("expected exactly one outcome mail, got %d", len(sent))
	}
	m := sent[0]
	if m.To != "reporter@example.com" || !strings.Contains(m.Text, "We took action on bad.loc.cc") || !strings.Contains(m.Subject, fmt.Sprintf("#%d", report.ID)) {
		t.Fatalf("unexpected outcome mail: %q %q", m.Subject, m.Text)
	}
	for _, part := range []string{m.Subject, m.Text, m.HTML} {
		if strings.Contains(part, "SECRET-ADMIN-NOTE") {
			t.Fatal("outcome mail leaked the admin note")
		}
	}

	put(gin.H{"status": "open"})
	put(gin.H{"status": "dismissed"})
	sent = fake.all()
	if len(sent) != 2 || !strings.Contains(sent[1].Text, "no violation") {
		t.Fatalf("reopen + dismiss should send a second, dismissal mail; got %d", len(sent))
	}

	silent := &models.AbuseReport{Subdomain: "x.loc.cc", Category: "spam", Details: "spam spam spam", Status: models.AbuseReportStatusOpen}
	db.Create(silent)
	if code, _ := doJSON(r, "PUT", fmt.Sprintf("/api/admin/abuse-reports/%d", silent.ID), gin.H{"status": "resolved"}); code != http.StatusOK {
		t.Fatal("update failed")
	}
	if len(fake.all()) != 2 {
		t.Fatal("mail sent for a report without a reporter email")
	}
}

func TestAbuseReportAlertsActiveAdmins(t *testing.T) {
	db := newTestDB(t)
	mailer, fake := syncMailer()
	h := NewAbuseReportHandler(db, nil, testConfig(), mailer)
	r := newAbuseRouter(h)
	createTestUser(t, db, "admin@example.com", true, func(u *models.User) { u.IsAdmin = true })
	createTestUser(t, db, "frozen-admin@example.com", true, func(u *models.User) { u.IsAdmin = true; u.Status = "frozen" })
	createTestUser(t, db, "member@example.com", true)

	code, body := doJSON(r, "POST", "/api/public/abuse-reports", gin.H{
		"subdomain": "evil.loc.cc", "category": "phishing", "details": "<b>fake bank login</b> page",
		"reporter_email": "r@example.com",
	}, "Accept-Language", "en-US")
	if code != http.StatusCreated {
		t.Fatalf("create report = %d %v", code, body)
	}
	var stored models.AbuseReport
	db.First(&stored)
	if stored.Locale != "en-US" {
		t.Fatalf("stored locale = %q, want en-US", stored.Locale)
	}

	sent := fake.all()
	if len(sent) != 1 || sent[0].To != "admin@example.com" {
		t.Fatalf("expected one alert to the active admin, got %+v", sent)
	}
	want := fmt.Sprintf("[Yunamo] New abuse report #%d: phishing · evil.loc.cc", stored.ID)
	if sent[0].Subject != want {
		t.Fatalf("alert subject = %q, want %q", sent[0].Subject, want)
	}
	if strings.Contains(sent[0].HTML, "<b>fake") || !strings.Contains(sent[0].HTML, "https://yunamo.com/admin/abuse-reports") || !strings.Contains(sent[0].Text, "r@example.com") {
		t.Fatal("alert HTML is not escaped or is missing the admin link / reporter email")
	}
}
