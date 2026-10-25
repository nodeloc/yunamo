package handler

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"opendomain/pkg/powerdns"
)

// maxCustomDSRecords bounds how many DS records an owner may publish for one
// delegation; two or three are enough for a key rollover.
const maxCustomDSRecords = 8

// dsAlgorithms are the DNSKEY algorithms accepted in a DS record (RFC 8624
// recommends these for signing; RSA/MD5, DSA and RSA/SHA-1 are rejected).
var dsAlgorithms = map[int]bool{8: true, 10: true, 13: true, 14: true, 15: true, 16: true}

// dsDigestLengths maps accepted digest types to their hex length. SHA-1
// (type 1) must no longer be published (RFC 8624 §3.3).
var dsDigestLengths = map[int]int{2: 64, 4: 96}

// normalizeDSRecords parses DS records supplied by the owner of fullDomain.
// Each entry may be the bare rdata ("4515 13 2 6F67...") or a full zone-file
// line ("tavis.loc.cc. 3600 IN DS 4515 13 2 6F67..."); a digest split by
// whitespace is joined. The result is the "keytag alg type digest" form with
// a lowercase digest, deduplicated.
func normalizeDSRecords(fullDomain string, raw []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, entry := range raw {
		fields := strings.Fields(entry)
		if len(fields) == 0 {
			continue
		}
		for i, f := range fields {
			if !strings.EqualFold(f, "DS") {
				continue
			}
			owner := strings.ToLower(strings.TrimSuffix(fields[0], "."))
			if i > 0 && owner != strings.ToLower(fullDomain) && owner != "@" && !isNumber(fields[0]) && !strings.EqualFold(fields[0], "IN") {
				return nil, fmt.Errorf("DS record %q is for %s, not %s", strings.TrimSpace(entry), owner, fullDomain)
			}
			fields = fields[i+1:]
			break
		}
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid DS record %q: expected \"<key tag> <algorithm> <digest type> <digest>\"", strings.TrimSpace(entry))
		}

		keyTag, err := strconv.Atoi(fields[0])
		if err != nil || keyTag < 0 || keyTag > 65535 {
			return nil, fmt.Errorf("invalid DS key tag %q", fields[0])
		}
		algorithm, err := strconv.Atoi(fields[1])
		if err != nil || !dsAlgorithms[algorithm] {
			return nil, fmt.Errorf("unsupported DS algorithm %q (accepted: 8, 10, 13, 14, 15, 16)", fields[1])
		}
		digestType, err := strconv.Atoi(fields[2])
		if err != nil || dsDigestLengths[digestType] == 0 {
			return nil, fmt.Errorf("unsupported DS digest type %q (accepted: 2 = SHA-256, 4 = SHA-384)", fields[2])
		}
		digest := strings.ToLower(strings.Join(fields[3:], ""))
		if _, err := hex.DecodeString(digest); err != nil || len(digest) != dsDigestLengths[digestType] {
			return nil, fmt.Errorf("invalid DS digest for digest type %d: expected %d hex characters", digestType, dsDigestLengths[digestType])
		}

		ds := fmt.Sprintf("%d %d %d %s", keyTag, algorithm, digestType, digest)
		if seen[ds] {
			continue
		}
		seen[ds] = true
		out = append(out, ds)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one DS record is required")
	}
	if len(out) > maxCustomDSRecords {
		return nil, fmt.Errorf("at most %d DS records can be published", maxCustomDSRecords)
	}
	return out, nil
}

// childZoneHostedLocally reports whether this PowerDNS serves childDomain
// itself. Only such a zone can be the source of the DS in the parent; for a
// domain on custom nameservers the DS was supplied by its owner.
func childZoneHostedLocally(pdns *powerdns.Client, childDomain string) (bool, error) {
	if _, err := pdns.GetZoneInfo(childDomain); err != nil {
		if powerdns.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// dropLocalDS removes the parent DS when it was generated from a local child
// zone, which is about to stop serving the domain (switch to custom NS). A
// DS the owner submitted for their custom nameservers is left alone, so NS
// re-syncs on renewal do not silently strip it.
func dropLocalDS(pdns *powerdns.Client, parentZone, childDomain string) error {
	local, err := childZoneHostedLocally(pdns, childDomain)
	if err != nil || !local {
		return err
	}
	return pdns.UnpublishDSFromParentZone(childDomain, parentZone)
}

// dropForeignDS removes a DS submitted for custom nameservers before the
// domain moves back to the local zone, which is unsigned when first created;
// keeping the old DS would make every answer BOGUS.
func dropForeignDS(pdns *powerdns.Client, parentZone, childDomain string) error {
	local, err := childZoneHostedLocally(pdns, childDomain)
	if err != nil || local {
		return err
	}
	return pdns.UnpublishDSFromParentZone(childDomain, parentZone)
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}
