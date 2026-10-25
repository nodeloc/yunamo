package powerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client PowerDNS API 客户端
type Client struct {
	BaseURL    string
	APIKey     string
	ServerID   string
	HTTPClient *http.Client
}

// NewClient 创建新的 PowerDNS 客户端
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL:  baseURL,
		APIKey:   apiKey,
		ServerID: "localhost", // 默认服务器 ID
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Zone 表示一个 DNS Zone
type Zone struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name"`
	Kind        string   `json:"kind"` // Master, Slave, Native
	DNSsec      bool     `json:"dnssec,omitempty"`
	APIRectify  bool     `json:"api_rectify,omitempty"`
	Serial      uint32   `json:"serial,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	RRsets      []RRset  `json:"rrsets,omitempty"`
}

// RRset 表示资源记录集
type RRset struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	TTL        int       `json:"ttl"`
	ChangeType string    `json:"changetype"` // REPLACE, DELETE
	Records    []Record  `json:"records,omitempty"`
	Comments   []Comment `json:"comments,omitempty"`
}

// Record 表示单条 DNS 记录
type Record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// Comment 表示记录注释
type Comment struct {
	Content    string `json:"content"`
	Account    string `json:"account,omitempty"`
	ModifiedAt int64  `json:"modified_at,omitempty"`
}

// CreateZone 创建新的 DNS Zone
func (c *Client) CreateZone(domain string, nameservers []string) error {
	zone := &Zone{
		Name:        ensureTrailingDot(domain),
		Kind:        "Master",
		Nameservers: nameservers,
		APIRectify:  true,
	}

	url := fmt.Sprintf("%s/api/v1/servers/%s/zones", c.BaseURL, c.ServerID)
	body, err := json.Marshal(zone)
	if err != nil {
		return fmt.Errorf("failed to marshal zone: %w", err)
	}

	_, err = c.doRequest("POST", url, body)
	return err
}

// GetZoneInfo returns zone metadata (kind, dnssec, serial...) without its RRsets.
func (c *Client) GetZoneInfo(domain string) (*Zone, error) {
	zoneName := ensureTrailingDot(domain)
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s?rrsets=false", c.BaseURL, c.ServerID, zoneName)

	respBody, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var zone Zone
	if err := json.Unmarshal(respBody, &zone); err != nil {
		return nil, fmt.Errorf("failed to unmarshal zone: %w", err)
	}
	return &zone, nil
}

// EnsureZone creates a zone when it does not already exist.
func (c *Client) EnsureZone(domain string, nameservers []string) error {
	if _, err := c.GetZoneInfo(domain); err == nil {
		return nil
	} else if !isNotFoundError(err) {
		return fmt.Errorf("failed to check zone %s: %w", domain, err)
	}

	if err := c.CreateZone(domain, nameservers); err != nil {
		// Another request may have created the zone after GetZone returned 404.
		if isConflictError(err) {
			return nil
		}
		return fmt.Errorf("failed to create zone %s: %w", domain, err)
	}
	return nil
}

// SetDelegation publishes the child zone's NS RRset in its parent zone.
// Creating a child zone in PowerDNS does not create this delegation automatically.
func (c *Client) SetDelegation(parentZone, childDomain string, nameservers []string) error {
	if len(nameservers) == 0 {
		return fmt.Errorf("cannot delegate %s without nameservers", childDomain)
	}

	entries := make([]RecordEntry, 0, len(nameservers))
	for _, ns := range nameservers {
		ns = strings.ToLower(strings.TrimSpace(ns))
		if ns == "" {
			return fmt.Errorf("cannot delegate %s to an empty nameserver", childDomain)
		}
		entries = append(entries, RecordEntry{Content: ensureTrailingDot(ns)})
	}

	// A CNAME left behind at the delegation point (legacy records stored in
	// the parent) conflicts with NS; drop it in the same PATCH, deletes first.
	rrsets := []RRset{
		{Name: ensureTrailingDot(childDomain), Type: "CNAME", ChangeType: "DELETE"},
		{Name: ensureTrailingDot(childDomain), Type: "NS", TTL: 3600, ChangeType: "REPLACE", Records: recordsFromEntries("NS", entries)},
	}
	if err := c.patchRRsets(ensureTrailingDot(parentZone), rrsets); err != nil {
		return fmt.Errorf("failed to publish delegation for %s in %s: %w", childDomain, parentZone, err)
	}
	if err := c.rectifyAfterPatch(parentZone); err != nil {
		return fmt.Errorf("failed to rectify parent zone %s: %w", parentZone, err)
	}
	return nil
}

// EnsureDelegatedZone makes the child authoritative before publishing its
// delegation. This ordering avoids exposing a lame delegation during creation.
func (c *Client) EnsureDelegatedZone(childDomain, parentZone string, nameservers []string) error {
	if err := c.EnsureZone(childDomain, nameservers); err != nil {
		return err
	}
	return c.SetDelegation(parentZone, childDomain, nameservers)
}

// RemoveDelegation removes both the DS chain and the NS delegation from the
// signed parent zone in one PATCH (DS first), then rectifies its
// denial-of-existence chain.
func (c *Client) RemoveDelegation(parentZone, childDomain string) error {
	name := ensureTrailingDot(childDomain)
	rrsets := []RRset{
		{Name: name, Type: "DS", ChangeType: "DELETE"},
		{Name: name, Type: "NS", ChangeType: "DELETE"},
	}
	if err := c.patchRRsets(ensureTrailingDot(parentZone), rrsets); err != nil {
		return fmt.Errorf("failed to remove delegation for %s from %s: %w", childDomain, parentZone, err)
	}
	if err := c.rectifyAfterPatch(parentZone); err != nil {
		return fmt.Errorf("failed to rectify parent zone %s: %w", parentZone, err)
	}
	return nil
}

// DeleteZone 删除 DNS Zone
func (c *Client) DeleteZone(domain string) error {
	zoneName := ensureTrailingDot(domain)
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", c.BaseURL, c.ServerID, zoneName)
	_, err := c.doRequest("DELETE", url, nil)
	return err
}

// GetZone 获取 Zone 信息
func (c *Client) GetZone(domain string) (*Zone, error) {
	zoneName := ensureTrailingDot(domain)
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", c.BaseURL, c.ServerID, zoneName)

	respBody, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var zone Zone
	if err := json.Unmarshal(respBody, &zone); err != nil {
		return nil, fmt.Errorf("failed to unmarshal zone: %w", err)
	}

	return &zone, nil
}

// RecordEntry 表示一条待同步的记录
type RecordEntry struct {
	Content  string
	Priority *int
}

// SetRecords 设置某个 name+type 的完整记录集（支持多条记录）
func (c *Client) SetRecords(domain, name, recordType string, entries []RecordEntry, ttl int) error {
	zoneName := ensureTrailingDot(domain)
	recordName := ensureTrailingDot(name)

	records := recordsFromEntries(recordType, entries)

	rrset := RRset{
		Name:       recordName,
		Type:       recordType,
		TTL:        ttl,
		ChangeType: "REPLACE",
		Records:    records,
	}

	return c.patchRRset(zoneName, rrset)
}

// recordsFromEntries renders RecordEntry values into PowerDNS record content.
func recordsFromEntries(recordType string, entries []RecordEntry) []Record {
	records := make([]Record, 0, len(entries))
	for _, e := range entries {
		var content string
		if recordType == "MX" && e.Priority != nil {
			content = fmt.Sprintf("%d %s", *e.Priority, ensureTrailingDot(e.Content))
		} else if recordType == "CNAME" || recordType == "NS" || recordType == "MX" {
			content = ensureTrailingDot(e.Content)
		} else {
			content = e.Content
		}
		records = append(records, Record{Content: content, Disabled: false})
	}
	return records
}

// DeleteRRset 删除某个 name+type 的所有记录
func (c *Client) DeleteRRset(domain, name, recordType string) error {
	zoneName := ensureTrailingDot(domain)
	recordName := ensureTrailingDot(name)

	rrset := RRset{
		Name:       recordName,
		Type:       recordType,
		ChangeType: "DELETE",
	}

	return c.patchRRset(zoneName, rrset)
}

// patchRRsets 批量发送多个 RRset patch 请求
func (c *Client) patchRRsets(zoneName string, rrsets []RRset) error {
	patchData := map[string][]RRset{
		"rrsets": rrsets,
	}

	body, err := json.Marshal(patchData)
	if err != nil {
		return fmt.Errorf("failed to marshal rrsets: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", c.BaseURL, c.ServerID, zoneName)
	_, err = c.doRequest("PATCH", url, body)
	return err
}

// SetSubdomainDisabled 将某个子域名下的所有记录设为 disabled/enabled
// subdomain 是完整子域名（如 "test.loc.cc"），会匹配该子域名及其子记录
func (c *Client) SetSubdomainDisabled(rootDomain, subdomain string, disabled bool) error {
	zoneName := ensureTrailingDot(rootDomain)

	// 获取 zone 的所有 RRsets
	zone, err := c.GetZone(rootDomain)
	if err != nil {
		return fmt.Errorf("failed to get zone: %w", err)
	}

	fqdnSuffix := ensureTrailingDot(subdomain)
	var patches []RRset

	for _, rrset := range zone.RRsets {
		// 跳过 SOA/NS 等系统记录
		if rrset.Type == "SOA" || rrset.Type == "NS" {
			continue
		}
		// 匹配属于该子域名的记录（精确匹配或子域名记录）
		if rrset.Name == fqdnSuffix || strings.HasSuffix(rrset.Name, "."+fqdnSuffix) {
			newRecords := make([]Record, len(rrset.Records))
			for i, r := range rrset.Records {
				newRecords[i] = Record{
					Content:  r.Content,
					Disabled: disabled,
				}
			}
			patches = append(patches, RRset{
				Name:       rrset.Name,
				Type:       rrset.Type,
				TTL:        rrset.TTL,
				ChangeType: "REPLACE",
				Records:    newRecords,
			})
		}
	}

	if len(patches) == 0 {
		return nil // 没有需要更新的记录
	}

	return c.patchRRsets(zoneName, patches)
}

// patchRRset 发送 RRset patch 请求
func (c *Client) patchRRset(zoneName string, rrset RRset) error {
	patchData := map[string][]RRset{
		"rrsets": {rrset},
	}

	body, err := json.Marshal(patchData)
	if err != nil {
		return fmt.Errorf("failed to marshal rrset: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", c.BaseURL, c.ServerID, zoneName)
	_, err = c.doRequest("PATCH", url, body)
	return err
}

// doRequest 执行 HTTP 请求
func (c *Client) doRequest(method, url string, body []byte) ([]byte, error) {
	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	unlock := lockZoneForWrite(method, url)
	defer unlock()

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// Ping checks that the PowerDNS API is reachable and accepts the API key.
func (c *Client) Ping(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/servers/%s", c.BaseURL, c.ServerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-API-Key", c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}
	return nil
}

// CryptoKey represents a DNSSEC cryptographic key returned by PowerDNS
type CryptoKey struct {
	ID        int      `json:"id"`
	KeyType   string   `json:"keytype"` // ksk, zsk, csk
	Active    bool     `json:"active"`
	Published bool     `json:"published"`
	DNSKey    string   `json:"dnskey"`
	DS        []string `json:"ds"`
	Flags     int      `json:"flags"`
	Algorithm string   `json:"algorithm"`
	Bits      int      `json:"bits"`
}

// dsRecordTTL is the TTL of DS records published at the parent delegation point.
// Kept short so that disabling DNSSEC (which removes the DS and then the keys)
// leaves resolvers with a stale DS for as little time as possible.
const dsRecordTTL = 300

// EnableDNSSEC enables DNSSEC for a zone by creating a CSK if none exist, then rectifies.
// The zone must already exist. Creating an active key implicitly enables DNSSEC in PowerDNS.
//
// The zone is also switched to API-RECTIFY so that every later record change
// keeps the NSEC ordering valid. Without that, zones created before rectify was
// enabled serve BOGUS denial-of-existence answers after their first edit.
func (c *Client) EnableDNSSEC(domain string) error {
	zoneName := ensureTrailingDot(domain)

	if err := c.updateZone(domain, map[string]interface{}{"api_rectify": true}); err != nil {
		return fmt.Errorf("failed to enable api-rectify on zone %s: %w", domain, err)
	}

	keys, err := c.GetCryptoKeys(domain)
	if err != nil {
		return fmt.Errorf("failed to list DNSSEC keys for %s: %w", domain, err)
	}

	hasActiveKey := false
	for _, k := range keys {
		if k.Active {
			hasActiveKey = true
			break
		}
	}

	if !hasActiveKey {
		keyURL := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s/cryptokeys", c.BaseURL, c.ServerID, zoneName)
		keyBody, _ := json.Marshal(map[string]interface{}{
			"keytype":   "csk",
			"active":    true,
			"published": true,
			"algorithm": "ECDSAP256SHA256",
		})
		if _, keyErr := c.doRequest("POST", keyURL, keyBody); keyErr != nil {
			return fmt.Errorf("failed to create DNSSEC key: %w", keyErr)
		}
	}

	// Rectify the zone to compute NSEC/NSEC3 records
	if err := c.RectifyZone(domain); err != nil {
		return fmt.Errorf("failed to rectify zone %s: %w", domain, err)
	}
	return nil
}

// DisableDNSSEC disables DNSSEC for a zone. PowerDNS removes all keys and
// NSEC3 parameters when dnssec is set to false.
func (c *Client) DisableDNSSEC(domain string) error {
	return c.updateZone(domain, map[string]interface{}{"dnssec": false})
}

// updateZone sends a partial zone metadata update (PUT /zones/{id}).
func (c *Client) updateZone(domain string, fields map[string]interface{}) error {
	zoneName := ensureTrailingDot(domain)
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s", c.BaseURL, c.ServerID, zoneName)
	body, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	_, err = c.doRequest("PUT", url, body)
	return err
}

// ActiveDSRecords returns the DS records of every active, published key of a zone.
func (c *Client) ActiveDSRecords(domain string) ([]string, error) {
	keys, err := c.GetCryptoKeys(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get crypto keys for %s: %w", domain, err)
	}
	var ds []string
	for _, k := range keys {
		if k.Active && k.Published {
			ds = append(ds, k.DS...)
		}
	}
	return ds, nil
}

// GetRRset returns the records of a single name+type in a zone, or nil when
// the RRset does not exist. It uses the rrset_name filter so that large
// parent zones are not transferred in full.
func (c *Client) GetRRset(domain, name, recordType string) ([]Record, error) {
	zoneName := ensureTrailingDot(domain)
	recordName := ensureTrailingDot(name)
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s?rrset_name=%s", c.BaseURL, c.ServerID, zoneName, recordName)

	respBody, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	var zone Zone
	if err := json.Unmarshal(respBody, &zone); err != nil {
		return nil, fmt.Errorf("failed to unmarshal zone: %w", err)
	}
	for _, rrset := range zone.RRsets {
		if strings.EqualFold(rrset.Name, recordName) && rrset.Type == recordType {
			return rrset.Records, nil
		}
	}
	return nil, nil
}

// IsNotFound reports whether err comes from a PowerDNS 404 / missing object.
func IsNotFound(err error) bool {
	return isNotFoundError(err)
}

// GetCryptoKeys returns all DNSSEC crypto keys for a zone
func (c *Client) GetCryptoKeys(domain string) ([]CryptoKey, error) {
	zoneName := ensureTrailingDot(domain)
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s/cryptokeys", c.BaseURL, c.ServerID, zoneName)
	respBody, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	var keys []CryptoKey
	if err := json.Unmarshal(respBody, &keys); err != nil {
		return nil, fmt.Errorf("failed to unmarshal crypto keys: %w", err)
	}
	return keys, nil
}

// RectifyZone computes NSEC/NSEC3 records and DNSSEC signatures for a zone
func (c *Client) RectifyZone(domain string) error {
	zoneName := ensureTrailingDot(domain)
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones/%s/rectify", c.BaseURL, c.ServerID, zoneName)
	_, err := c.doRequest("PUT", url, nil)
	return err
}

// rectifyAfterPatch rectifies a zone after an RRset PATCH unless the zone has
// API-RECTIFY, in which case PowerDNS already rectified it inside the PATCH
// transaction. On a large signed zone each rectify rewrites thousands of rows,
// so a redundant one doubles the lock time.
func (c *Client) rectifyAfterPatch(domain string) error {
	if info, err := c.GetZoneInfo(domain); err == nil && info.APIRectify {
		return nil
	}
	return c.RectifyZone(domain)
}

// zoneWriteLocks serializes write requests to the same zone across every
// Client in the process. Concurrent PATCH/rectify transactions on a large
// signed zone deadlock in the PowerDNS MySQL backend or outlive its query
// timeout, which surfaces as HTTP 500.
var zoneWriteLocks sync.Map // lower-cased zone name -> *sync.Mutex

func lockZoneForWrite(method, rawURL string) func() {
	if method == http.MethodGet {
		return func() {}
	}
	zone := zoneFromURL(rawURL)
	if zone == "" {
		return func() {}
	}
	m, _ := zoneWriteLocks.LoadOrStore(zone, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func zoneFromURL(rawURL string) string {
	const marker = "/zones/"
	i := strings.Index(rawURL, marker)
	if i < 0 {
		return ""
	}
	zone := rawURL[i+len(marker):]
	if j := strings.IndexAny(zone, "/?"); j >= 0 {
		zone = zone[:j]
	}
	return strings.ToLower(zone)
}

// PublishDSToParentZone reads the DS records from the child zone's crypto keys
// and writes them as a DS RRset into the parent zone at the delegation point,
// then rectifies the parent so its NSEC chain covers the new delegation data.
func (c *Client) PublishDSToParentZone(childDomain, parentZone string) error {
	dsContents, err := c.ActiveDSRecords(childDomain)
	if err != nil {
		return err
	}
	if len(dsContents) == 0 {
		return fmt.Errorf("no active DS records found for %s", childDomain)
	}
	return c.SetParentDS(parentZone, childDomain, dsContents)
}

// SetParentDS replaces the DS RRset of childDomain in the parent zone with the
// given records and rectifies the parent. It is used directly for children
// signed elsewhere (custom nameservers), whose DS the owner supplies.
func (c *Client) SetParentDS(parentZone, childDomain string, dsContents []string) error {
	if len(dsContents) == 0 {
		return fmt.Errorf("no DS records to publish for %s", childDomain)
	}
	entries := make([]RecordEntry, len(dsContents))
	for i, ds := range dsContents {
		entries[i] = RecordEntry{Content: ds}
	}

	if err := c.SetRecords(parentZone, childDomain, "DS", entries, dsRecordTTL); err != nil {
		return fmt.Errorf("failed to publish DS for %s in %s: %w", childDomain, parentZone, err)
	}
	if err := c.rectifyAfterPatch(parentZone); err != nil {
		return fmt.Errorf("failed to rectify parent zone %s: %w", parentZone, err)
	}
	return nil
}

// UnpublishDSFromParentZone removes the DS RRset of the child zone from the
// parent zone and rectifies the parent.
func (c *Client) UnpublishDSFromParentZone(childDomain, parentZone string) error {
	if err := c.DeleteRRset(parentZone, childDomain, "DS"); err != nil {
		return fmt.Errorf("failed to remove DS for %s from %s: %w", childDomain, parentZone, err)
	}
	if err := c.rectifyAfterPatch(parentZone); err != nil {
		return fmt.Errorf("failed to rectify parent zone %s: %w", parentZone, err)
	}
	return nil
}

// ListZones returns every zone known to the server (metadata only, no RRsets).
func (c *Client) ListZones() ([]Zone, error) {
	url := fmt.Sprintf("%s/api/v1/servers/%s/zones", c.BaseURL, c.ServerID)
	respBody, err := c.doRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	var zones []Zone
	if err := json.Unmarshal(respBody, &zones); err != nil {
		return nil, fmt.Errorf("failed to unmarshal zones: %w", err)
	}
	return zones, nil
}

// EnableAPIRectify switches a zone to API-RECTIFY so later API edits keep
// its NSEC ordering valid.
func (c *Client) EnableAPIRectify(domain string) error {
	return c.updateZone(domain, map[string]interface{}{"api_rectify": true})
}

// Delegation describes a child delegation to publish in a parent zone.
type Delegation struct {
	Child       string
	Nameservers []string
	DS          []string // optional; empty means "no DS" (insecure delegation)
}

// delegationBatchSize bounds the number of delegations sent in one PATCH.
const delegationBatchSize = 40

// rrsetsPerDelegation is the fixed number of RRsets emitted per delegation:
// CNAME DELETE (clears legacy conflicts), NS REPLACE, DS REPLACE/DELETE.
const rrsetsPerDelegation = 3

func delegationRRsets(d Delegation) ([]RRset, error) {
	if len(d.Nameservers) == 0 {
		return nil, fmt.Errorf("cannot delegate %s without nameservers", d.Child)
	}
	name := ensureTrailingDot(d.Child)
	ns := make([]Record, 0, len(d.Nameservers))
	for _, n := range d.Nameservers {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			return nil, fmt.Errorf("cannot delegate %s to an empty nameserver", d.Child)
		}
		ns = append(ns, Record{Content: ensureTrailingDot(n)})
	}
	dsRRset := RRset{Name: name, Type: "DS", TTL: dsRecordTTL, ChangeType: "DELETE"}
	if len(d.DS) > 0 {
		dsRRset.ChangeType = "REPLACE"
		for _, ds := range d.DS {
			dsRRset.Records = append(dsRRset.Records, Record{Content: ds})
		}
	}
	return []RRset{
		{Name: name, Type: "CNAME", ChangeType: "DELETE"},
		{Name: name, Type: "NS", TTL: 3600, ChangeType: "REPLACE", Records: ns},
		dsRRset,
	}, nil
}

// SetDelegations publishes many NS (and optional DS) delegations in the parent
// zone using batched PATCH requests, then rectifies the parent once. It is
// meant for bulk repair; use SetDelegation/PublishDSToParentZone for single
// domains. A delegation that PowerDNS rejects is retried on its own and
// reported through DelegationErrors while the others are still published.
func (c *Client) SetDelegations(parentZone string, delegations []Delegation) error {
	zoneName := ensureTrailingDot(parentZone)
	var rrsets []RRset
	for _, d := range delegations {
		rs, err := delegationRRsets(d)
		if err != nil {
			return err
		}
		rrsets = append(rrsets, rs...)
	}
	if len(rrsets) == 0 {
		return nil
	}

	step := delegationBatchSize * rrsetsPerDelegation
	var failures []error
	for start := 0; start < len(rrsets); start += step {
		end := start + step
		if end > len(rrsets) {
			end = len(rrsets)
		}
		if err := c.patchRRsets(zoneName, rrsets[start:end]); err == nil {
			continue
		}
		for i := start; i < end; i += rrsetsPerDelegation {
			if err := c.patchRRsets(zoneName, rrsets[i:i+rrsetsPerDelegation]); err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", strings.TrimSuffix(rrsets[i].Name, "."), err))
			}
		}
	}
	if err := c.rectifyAfterPatch(parentZone); err != nil {
		return fmt.Errorf("failed to rectify parent zone %s: %w", parentZone, err)
	}
	if len(failures) > 0 {
		return &DelegationErrors{Parent: parentZone, Failures: failures}
	}
	return nil
}

// DelegationErrors reports the delegations that could not be published while
// the rest of the batch succeeded.
type DelegationErrors struct {
	Parent   string
	Failures []error
}

func (e *DelegationErrors) Error() string {
	msgs := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		msgs = append(msgs, f.Error())
	}
	return fmt.Sprintf("%d delegation(s) failed in %s: %s", len(e.Failures), e.Parent, strings.Join(msgs, "; "))
}

// toggleRRsets re-publishes the given RRsets with every record's disabled
// flag set to `disabled`, in batches.
func (c *Client) toggleRRsets(zoneName string, rrsets []RRset, disabled bool) error {
	var patches []RRset
	for _, rrset := range rrsets {
		records := make([]Record, len(rrset.Records))
		for i, r := range rrset.Records {
			records[i] = Record{Content: r.Content, Disabled: disabled}
		}
		patches = append(patches, RRset{
			Name: rrset.Name, Type: rrset.Type, TTL: rrset.TTL,
			ChangeType: "REPLACE", Records: records,
		})
	}
	for start := 0; start < len(patches); start += delegationBatchSize * rrsetsPerDelegation {
		end := start + delegationBatchSize*rrsetsPerDelegation
		if end > len(patches) {
			end = len(patches)
		}
		if err := c.patchRRsets(zoneName, patches[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// SetDomainSuspended makes a subdomain stop (or resume) resolving:
//
//   - in the child zone (when one exists) every record except SOA and the apex
//     NS is disabled, so the zone answers NODATA for everything;
//   - in the parent zone, legacy records at or below the name are disabled;
//     the NS/DS delegation is disabled only when there is no child zone
//     (custom nameservers), so the parent answers NXDOMAIN. With a child zone
//     the delegation is kept so signed NODATA answers still validate.
//
// PowerDNS treats disabled records as nonexistent, so this is reversible and
// keeps the operator's data intact.
func (c *Client) SetDomainSuspended(parentZone, childDomain string, suspended bool) error {
	childName := ensureTrailingDot(strings.ToLower(childDomain))
	childZoneExists := false
	child, err := c.GetZone(childDomain)
	if err == nil {
		childZoneExists = true
	} else if !isNotFoundError(err) {
		return fmt.Errorf("failed to read child zone %s: %w", childDomain, err)
	}

	parent, err := c.GetZone(parentZone)
	if err != nil {
		return fmt.Errorf("failed to read parent zone %s: %w", parentZone, err)
	}
	var parentTargets []RRset
	for _, rrset := range parent.RRsets {
		name := strings.ToLower(rrset.Name)
		if name != childName && !strings.HasSuffix(name, "."+childName) {
			continue
		}
		if rrset.Type == "SOA" {
			continue
		}
		if (rrset.Type == "NS" || rrset.Type == "DS") && name == childName && childZoneExists {
			continue
		}
		parentTargets = append(parentTargets, rrset)
	}
	if err := c.toggleRRsets(ensureTrailingDot(parentZone), parentTargets, suspended); err != nil {
		return fmt.Errorf("failed to update parent zone %s: %w", parentZone, err)
	}

	if childZoneExists {
		var childTargets []RRset
		for _, rrset := range child.RRsets {
			if rrset.Type == "SOA" {
				continue
			}
			if rrset.Type == "NS" && strings.EqualFold(rrset.Name, childName) {
				continue
			}
			childTargets = append(childTargets, rrset)
		}
		if err := c.toggleRRsets(childName, childTargets, suspended); err != nil {
			return fmt.Errorf("failed to update child zone %s: %w", childDomain, err)
		}
	}
	return nil
}

// RemoveDelegations deletes the NS and DS RRsets of many children from the
// parent zone in batches and rectifies the parent once.
func (c *Client) RemoveDelegations(parentZone string, children []string) error {
	if len(children) == 0 {
		return nil
	}
	zoneName := ensureTrailingDot(parentZone)
	var rrsets []RRset
	for _, child := range children {
		name := ensureTrailingDot(child)
		rrsets = append(rrsets,
			RRset{Name: name, Type: "DS", ChangeType: "DELETE"},
			RRset{Name: name, Type: "NS", ChangeType: "DELETE"},
		)
	}
	step := delegationBatchSize * rrsetsPerDelegation
	for start := 0; start < len(rrsets); start += step {
		end := start + step
		if end > len(rrsets) {
			end = len(rrsets)
		}
		if err := c.patchRRsets(zoneName, rrsets[start:end]); err != nil {
			return fmt.Errorf("failed to remove delegations from %s: %w", parentZone, err)
		}
	}
	if err := c.rectifyAfterPatch(parentZone); err != nil {
		return fmt.Errorf("failed to rectify parent zone %s: %w", parentZone, err)
	}
	return nil
}

// ensureTrailingDot 确保域名以点结尾
func ensureTrailingDot(s string) string {
	if len(s) == 0 {
		return s
	}
	if s[len(s)-1] != '.' {
		return s + "."
	}
	return s
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "status 404") ||
		strings.Contains(message, "not found") ||
		strings.Contains(message, "could not find")
}

func isConflictError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "status 409") ||
		strings.Contains(message, "status 422") ||
		strings.Contains(message, "conflict") ||
		strings.Contains(message, "already exists")
}
