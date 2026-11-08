package config

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestDefaultTrustedProxiesResolveClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := r.SetTrustedProxies(parseTrustedProxies("")); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}
	r.GET("/ip", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })

	cases := []struct {
		name   string
		remote string
		xff    string
		want   string
	}{
		{"direct client spoofing XFF is ignored", "203.0.113.7:1234", "9.9.9.9", "203.0.113.7"},
		{"via nginx and Cloudflare", "172.18.0.1:5555", "198.51.100.20, 162.158.1.1", "198.51.100.20"},
		{"client-forged prefix is skipped", "172.18.0.1:5555", "6.6.6.6, 198.51.100.20, 162.158.1.1", "198.51.100.20"},
		{"bypassing Cloudflare to nginx", "172.18.0.1:5555", "6.6.6.6, 203.0.113.9", "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ip", nil)
			req.RemoteAddr = tc.remote
			req.Header.Set("X-Forwarded-For", tc.xff)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if got := w.Body.String(); got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTrustedProxiesOverride(t *testing.T) {
	got := parseTrustedProxies(" 10.0.0.1 , ,192.168.1.0/24")
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "192.168.1.0/24" {
		t.Fatalf("unexpected: %v", got)
	}
}
