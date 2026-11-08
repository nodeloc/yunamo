package middleware

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestTokenRevokedByPasswordChange(t *testing.T) {
	changed := time.Date(2026, 11, 8, 10, 0, 0, 500_000_000, time.UTC)
	iat := func(ts time.Time) *Claims {
		return &Claims{RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(ts)}}
	}
	cases := []struct {
		name    string
		claims  *Claims
		changed *time.Time
		want    bool
	}{
		{"never changed", iat(changed.Add(-time.Hour)), nil, false},
		{"issued before change", iat(changed.Add(-time.Minute)), &changed, true},
		{"issued same second", iat(changed), &changed, false},
		{"issued after change", iat(changed.Add(time.Minute)), &changed, false},
		{"no iat", &Claims{}, &changed, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenRevokedByPasswordChange(tc.claims, tc.changed); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
