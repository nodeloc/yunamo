package handler

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"opendomain/pkg/powerdns"
)

const testDigest = "6F67842BEB0A6A61B19CEFEA2CC26F5ABDE711E138A2150B93BD14E18E64DBA2"

func TestNormalizeDSRecordsAcceptsRdataAndZoneFileLines(t *testing.T) {
	want := []string{"4515 13 2 " + strings.ToLower(testDigest)}
	inputs := [][]string{
		{"4515 13 2 " + testDigest},
		{"tavis.loc.cc. IN DS 4515 13 2 " + testDigest},
		{"tavis.loc.cc. 3600 IN DS 4515 13 2 " + testDigest},
		{"@ IN DS 4515 13 2 " + testDigest},
		{"4515 13 2 " + testDigest[:32] + " " + testDigest[32:]},
		{"4515 13 2 " + testDigest, "", "4515 13 2 " + strings.ToLower(testDigest)},
	}
	for _, in := range inputs {
		got, err := normalizeDSRecords("tavis.loc.cc", in)
		if err != nil {
			t.Fatalf("normalizeDSRecords(%q): %v", in, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("normalizeDSRecords(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormalizeDSRecordsRejectsBadInput(t *testing.T) {
	sha1 := "4515 13 1 " + strings.Repeat("ab", 20)
	for _, bad := range [][]string{
		nil,
		{"   "},
		{"4515 13 2"},
		{"other.loc.cc. IN DS 4515 13 2 " + testDigest},
		{"70000 13 2 " + testDigest},
		{"4515 5 2 " + testDigest},
		{sha1},
		{"4515 13 2 " + testDigest[:60]},
		{"4515 13 2 " + strings.Repeat("zz", 32)},
		{"4515 13 4 " + testDigest},
	} {
		if got, err := normalizeDSRecords("tavis.loc.cc", bad); err == nil {
			t.Fatalf("normalizeDSRecords(%q) = %v, want error", bad, got)
		}
	}
}

func TestNormalizeDSRecordsLimitsCount(t *testing.T) {
	var many []string
	for i := 0; i <= maxCustomDSRecords; i++ {
		many = append(many, strings.Replace("KEY 13 2 "+testDigest, "KEY", string(rune('1'+i)), 1))
	}
	if _, err := normalizeDSRecords("tavis.loc.cc", many); err == nil {
		t.Fatalf("expected an error for %d records", len(many))
	}
}

// pdnsZoneServer answers GET zone info for child.loc.cc with 200 or 404 and
// records every request.
func pdnsZoneServer(t *testing.T, childHosted bool, calls *[]string) *powerdns.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls = append(*calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/servers/localhost/zones/child.loc.cc.":
			if !childHosted {
				http.Error(w, `{"error":"Could not find domain 'child.loc.cc.'"}`, http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"name":"child.loc.cc.","dnssec":true}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"name":"loc.cc.","api_rectify":true}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)
	return powerdns.NewClient(server.URL, "test-key")
}

func TestDropLocalDSKeepsCustomNameserverDS(t *testing.T) {
	var calls []string
	client := pdnsZoneServer(t, false, &calls)
	if err := dropLocalDS(client, "loc.cc", "child.loc.cc"); err != nil {
		t.Fatalf("dropLocalDS: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("custom-NS DS must survive an NS re-sync, got calls %v", calls)
	}
}

func TestDropLocalDSRemovesDSOfLocalZone(t *testing.T) {
	var calls []string
	client := pdnsZoneServer(t, true, &calls)
	if err := dropLocalDS(client, "loc.cc", "child.loc.cc"); err != nil {
		t.Fatalf("dropLocalDS: %v", err)
	}
	if len(calls) < 2 || calls[1] != "PATCH /api/v1/servers/localhost/zones/loc.cc." {
		t.Fatalf("expected the parent DS to be deleted, got calls %v", calls)
	}
}

func TestDropForeignDSRemovesDSBeforeLocalZoneExists(t *testing.T) {
	var calls []string
	client := pdnsZoneServer(t, false, &calls)
	if err := dropForeignDS(client, "loc.cc", "child.loc.cc"); err != nil {
		t.Fatalf("dropForeignDS: %v", err)
	}
	if len(calls) < 2 || calls[1] != "PATCH /api/v1/servers/localhost/zones/loc.cc." {
		t.Fatalf("expected the custom-NS DS to be deleted, got calls %v", calls)
	}
}

func TestDropForeignDSKeepsDSOfLocalZone(t *testing.T) {
	var calls []string
	client := pdnsZoneServer(t, true, &calls)
	if err := dropForeignDS(client, "loc.cc", "child.loc.cc"); err != nil {
		t.Fatalf("dropForeignDS: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("DS of the signed local zone must be kept, got calls %v", calls)
	}
}
