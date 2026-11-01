package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"opendomain/internal/models"
)

func TestValidateDNSTarget(t *testing.T) {
	cases := []struct {
		content string
		ok      bool
	}{
		{"target.example.com", true},
		{"target.example.com.", true},
		{"www", true},
		{"_abc123.acm-validations.aws.", true},
		{"selector1-contoso-com._domainkey.contoso.onmicrosoft.com", true},
		{"", false},
		{"bad host.example.com", false},
		{"a..b", false},
		{"x'..y", false},
		{`x".example.com`, false},
		{"target.example.com\n", false},
		{strings.Repeat("a", 64) + ".example.com", false},
	}
	for _, typ := range []string{"CNAME", "ALIAS"} {
		for _, c := range cases {
			if err := validateDNSRecord(typ, c.content); (err == nil) != c.ok {
				t.Errorf("validateDNSRecord(%s, %q) err=%v, want ok=%v", typ, c.content, err, c.ok)
			}
		}
	}
}

func TestLuaCNAMEEntry(t *testing.T) {
	entry, err := luaCNAMEEntry("'target.example.com.'")
	if err != nil {
		t.Fatalf("valid target: %v", err)
	}
	if want := `CNAME ";return 'target.example.com.'"`; entry.Content != want {
		t.Fatalf("content = %s, want %s", entry.Content, want)
	}

	// Records stored before validation existed must not reach the Lua source.
	for _, content := range []string{"x'..y..'z", `x".example.com`, "a b.example.com", "x\n.example.com"} {
		if entry, err := luaCNAMEEntry(content); err == nil {
			t.Errorf("luaCNAMEEntry(%q) = %q, want error", content, entry.Content)
		}
	}
}

func newDNSRouter(t *testing.T, content string) (*gin.Engine, *models.DNSRecord) {
	t.Helper()
	db := newTestDB(t)
	if err := db.AutoMigrate(&models.RootDomain{}, &models.Domain{}, &models.DNSRecord{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	u := createTestUser(t, db, "dns@example.com", true)
	root := &models.RootDomain{Domain: "loc.cc", Nameservers: "[]", IsActive: true}
	if err := db.Create(root).Error; err != nil {
		t.Fatalf("create root domain: %v", err)
	}
	d := &models.Domain{UserID: u.ID, RootDomainID: root.ID, Subdomain: "aaa", FullDomain: "aaa.loc.cc", Status: "active",
		RegisteredAt: time.Now(), ExpiresAt: time.Now().AddDate(1, 0, 0), UseDefaultNameservers: true}
	if err := db.Create(d).Error; err != nil {
		t.Fatalf("create domain: %v", err)
	}
	rec := &models.DNSRecord{DomainID: d.ID, Name: "@", Type: "CNAME", Content: content, TTL: 300, IsActive: true}
	if err := db.Create(rec).Error; err != nil {
		t.Fatalf("create record: %v", err)
	}
	h := NewDNSHandler(db, testConfig())
	r := gin.New()
	r.Use(withUser(u.ID))
	r.POST("/dns/:domainId/records", h.CreateRecord)
	r.PUT("/dns/:domainId/records/:recordId", h.UpdateRecord)
	return r, rec
}

func TestUpdateRecordValidatesContentChanges(t *testing.T) {
	r, _ := newDNSRouter(t, "target.example.com")

	if code, body := doJSON(r, "PUT", "/dns/1/records/1", gin.H{"content": "x'..y..'z"}); code != http.StatusBadRequest {
		t.Fatalf("unsafe content = %d %v, want 400", code, body)
	}
	if code, body := doJSON(r, "PUT", "/dns/1/records/1", gin.H{"content": "_abc.acm-validations.aws."}); code != http.StatusOK {
		t.Fatalf("underscore target = %d %v, want 200", code, body)
	}
	if code, body := doJSON(r, "PUT", "/dns/1/records/1", gin.H{"type": "LUA"}); code != http.StatusBadRequest {
		t.Fatalf("LUA type = %d %v, want 400", code, body)
	}
}

func TestUpdateRecordKeepsLegacyContentEditable(t *testing.T) {
	r, _ := newDNSRouter(t, "legacy value")

	if code, body := doJSON(r, "PUT", "/dns/1/records/1", gin.H{"ttl": 600}); code != http.StatusOK {
		t.Fatalf("ttl only = %d %v, want 200", code, body)
	}
	if code, body := doJSON(r, "PUT", "/dns/1/records/1", gin.H{"is_active": false}); code != http.StatusOK {
		t.Fatalf("disable = %d %v, want 200", code, body)
	}
}

func TestCreateRecordStripsQuotesBeforeValidating(t *testing.T) {
	r, _ := newDNSRouter(t, "target.example.com")

	if code, body := doJSON(r, "POST", "/dns/1/records", gin.H{"name": "www", "type": "CNAME", "content": "'quoted.example.com'", "ttl": 300}); code != http.StatusOK {
		t.Fatalf("quoted target = %d %v, want 200", code, body)
	}
	if code, body := doJSON(r, "POST", "/dns/1/records", gin.H{"name": "bad", "type": "CNAME", "content": "x'..y..'z", "ttl": 300}); code != http.StatusBadRequest {
		t.Fatalf("unsafe target = %d %v, want 400", code, body)
	}
}
