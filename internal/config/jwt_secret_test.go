package config

import "testing"

func TestValidateJWTSecret(t *testing.T) {
	cases := []struct {
		name    string
		secret  string
		wantErr bool
	}{
		{"empty", "", true},
		{"env example placeholder", "your-super-secret-jwt-key-change-this-in-production", true},
		{"compose placeholder", "change-this-secret-key", true},
		{"too short", "abcdefghijklmnopqrstuvwxyz01234", true},
		{"random 32 chars", "0123456789abcdef0123456789abcdef", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateJWTSecret(tc.secret); (err != nil) != tc.wantErr {
				t.Fatalf("validateJWTSecret(%q) error = %v, wantErr %v", tc.secret, err, tc.wantErr)
			}
		})
	}
}
