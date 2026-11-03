package handler

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

// A and AAAA used to be validated with a "contains a colon" check and a
// trim-then-validate path, so whitespace and v4-mapped IPv6 values reached
// PowerDNS (which answers 422 for them).
func TestValidateDNSRecordAddresses(t *testing.T) {
	cases := []struct {
		typ     string
		content string
		ok      bool
	}{
		{"A", "192.0.2.10", true},
		{"A", "999.1.1.1", false},
		{"A", "not-an-ip", false},
		{"A", " 192.0.2.10", false},
		{"A", "192.0.2.10 ", false},
		{"A", "192.0.2.10\n", false},
		{"A", "::ffff:192.0.2.10", false}, // v4-mapped IPv6 is not an A value
		{"AAAA", "2001:db8::1", true},
		{"AAAA", "::1", true},
		{"AAAA", "192.0.2.10", false},
		{"AAAA", "gggg::1", false},
		{"AAAA", " 2001:db8::1", false},
	}
	for _, c := range cases {
		if err := validateDNSRecord(c.typ, c.content); (err == nil) != c.ok {
			t.Errorf("validateDNSRecord(%q, %q) err=%v, want ok=%v", c.typ, c.content, err, c.ok)
		}
	}
}

// NS and MX targets must be real host names; CNAME/ALIAS stay permissive
// (isValidDNSTarget, covered in dns_target_test.go). Null MX is RFC 7505.
func TestValidateDNSRecordTargets(t *testing.T) {
	cases := []struct {
		typ     string
		content string
		ok      bool
	}{
		{"NS", "ns1.example.com", true},
		{"NS", "ns1.example.com.", true},
		{"NS", "_ns.example.com", false},
		{"NS", "ns 1.example.com", false},
		{"NS", "ns1", false},
		{"MX", "mail.example.com", true},
		{"MX", "mail.example.com.", true},
		{"MX", ".", true}, // RFC 7505 null MX
		{"MX", "_mail.example.com", false},
		{"MX", "-bad.example.com", false},
		{"MX", "mail example.com", false},
	}
	for _, c := range cases {
		if err := validateDNSRecord(c.typ, c.content); (err == nil) != c.ok {
			t.Errorf("validateDNSRecord(%q, %q) err=%v, want ok=%v", c.typ, c.content, err, c.ok)
		}
	}
}

func TestCreateRecordAcceptsNullMX(t *testing.T) {
	r, _ := newDNSRouter(t, "target.example.com")

	if code, body := doJSON(r, "POST", "/dns/1/records", gin.H{
		"name": "nullmx", "type": "MX", "content": ".", "priority": 0, "ttl": 300,
	}); code != http.StatusOK {
		t.Fatalf("null MX = %d %v, want 200", code, body)
	}
	if code, body := doJSON(r, "POST", "/dns/1/records", gin.H{
		"name": "badaaaa", "type": "A", "content": "::ffff:192.0.2.10", "ttl": 300,
	}); code != http.StatusBadRequest {
		t.Fatalf("v4-mapped A = %d %v, want 400", code, body)
	}
}
