# OpenDomain Documentation

## Table of Contents

- [Documentation](#documentation)
- [API Reference](#api-reference)
- [FAQ](#faq)
- [Support](#support)

---

# Documentation

## Overview

**OpenDomain** is an open-source **free subdomain distribution platform**. It allows users to register and self-manage custom subdomains (e.g., `mysite.example.com`) backed by **PowerDNS**. The platform supports paid domains via the NodeLoc payment gateway, a coupon and invitation system, domain health scanning, and CyberPanel web hosting integration.

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Go 1.24 · Gin · GORM |
| Database | PostgreSQL 15 |
| Cache | Redis 7 |
| DNS Engine | PowerDNS (REST API) |
| Frontend | Vue 3 · Vue Router · Pinia |
| Authentication | Local (email + password) · GitHub OAuth · Google OAuth · NodeLoc OAuth |
| Payment | NodeLoc Payment Gateway |
| Web Hosting | CyberPanel API |
| Internationalization | Request-level i18n middleware |

## Deployment

### Requirements

- Docker & Docker Compose
- PostgreSQL 15+
- Redis 7+
- PowerDNS with REST API enabled

### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd opendomain

# Copy and edit environment variables
cp .env.example .env

# Start all services (includes database migration)
docker-compose up -d

# Development mode
docker-compose -f docker-compose.dev.yml up -d
```

### Environment Variables

| Category | Key Variables |
|---|---|
| Application | `APP_ENV`, `PORT`, `FRONTEND_URL`, `SITE_NAME`, `SITE_DESCRIPTION` |
| Database | `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_SSL_MODE` |
| Redis | `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_DB` |
| JWT | `JWT_SECRET`, `JWT_EXPIRES_IN` |
| PowerDNS | `POWERDNS_API_URL`, `POWERDNS_API_KEY` |
| Default Nameservers | `DEFAULT_NS1`, `DEFAULT_NS2` |
| Payment | `NODELOC_PAYMENT_ID`, `NODELOC_SECRET_KEY`, `PAYMENT_CALLBACK_URL`, `PAYMENT_TEST_MODE` |
| OAuth | `GITHUB_CLIENT_ID/SECRET`, `GOOGLE_CLIENT_ID/SECRET`, `NODELOC_CLIENT_ID/SECRET` |
| Scanner | `GOOGLE_SAFE_BROWSING_KEY`, `VIRUSTOTAL_API_KEY`, `SCANNER_CONCURRENCY`, `SCANNER_TIMEOUT` |
| CyberPanel | `CYBERPANEL_ENCRYPTION_KEY` |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHANNEL_ID` |

## User Levels

The platform uses 5 user levels that affect domain quota and access to premium root domains:

| Level | Name |
|---|---|
| 1 | normal |
| 2 | basic |
| 3 | member |
| 4 | regular |
| 5 | leader |

## Features

### Subdomain Registration

Users select a subdomain prefix and a root domain (e.g., `example.com`), check availability, and complete registration. Root domains can be configured as free or paid and may require a minimum user level.

### DNS Management

Full CRUD support for A, AAAA, CNAME, ALIAS, MX, TXT, NS, SRV, and CAA records. All changes are synced in real time to PowerDNS. DNSSEC is supported, including enable/disable and DS record publishing.

### Payments & Orders

Paid domain registrations are processed via the NodeLoc payment gateway. Coupons support percentage discounts, fixed discounts, and quota increases. Free orders can be completed instantly without entering payment.

### Invitation System

Users can generate invitation codes. When a new user registers using an invitation code, both parties receive a configurable reward (e.g., increased quota or level upgrade).

### Domain Health Scanning

The platform periodically scans all domains for:

- HTTP reachability
- DNS resolution
- SSL certificate validity
- Google Safe Browsing status
- VirusTotal detection

Overall health is reported as `healthy`, `degraded`, or `down`. Domains that remain unhealthy can be automatically suspended.

### Web Hosting (CyberPanel)

Users can request a web hosting account linked to one of their active domains. Hosting accounts are provisioned on CyberPanel servers configured by the administrator.

### Announcements & Custom Pages

Administrators can publish announcements (categories: general, maintenance, update, important) and custom slug-based static pages displayed in the frontend.

## Frontend Pages

| Route | View | Auth Required | Description |
|---|---|---|---|
| `/` | Home | No | Landing page with domain search |
| `/login` | Login | No | Login form |
| `/register` | Register | No | Registration with optional invite code |
| `/auth/callback` | AuthCallback | No | OAuth redirect handler |
| `/dashboard` | Dashboard | Yes | User dashboard |
| `/domains` | Domains | Yes | My domains list |
| `/domains/:domainId/dns` | DNSManagement | Yes | DNS record editor |
| `/profile` | Profile | Yes | User profile settings |
| `/coupons` | Coupons | Yes | Coupon redemption |
| `/invitations` | Invitations | Yes | Referral and invitation system |
| `/checkout` | DomainCheckout | Yes | Order checkout flow |
| `/orders` | OrderList | Yes | Order history |
| `/payment/success` | PaymentCallback | No | Payment success page |
| `/payment/failure` | PaymentCallback | No | Payment failure page |
| `/announcements` | Announcements | No | Announcement list |
| `/announcements/:id` | AnnouncementDetail | No | Announcement detail |
| `/domain-health` | DomainHealth | No | Public domain health board |
| `/pages/:slug` | PageView | No | Custom static pages |
| `/whois/:domain` | WhoisDetail | No | WHOIS lookup result |
| `/admin` | AdminDashboard | Admin | Admin dashboard and statistics |
| `/admin/users` | AdminUsers | Admin | User management |
| `/admin/domains` | AdminDomains | Admin | All domains management |
| `/admin/root-domains` | AdminRootDomains | Admin | Root domain CRUD |
| `/admin/coupons` | AdminCoupons | Admin | Coupon management |
| `/admin/announcements` | AdminAnnouncements | Admin | Announcement management |
| `/admin/pages` | AdminPages | Admin | Custom page management |
| `/admin/orders` | AdminOrders | Admin | All orders |
| `/admin/settings` | AdminSettings | Admin | Site and system settings |
| `/admin/scan-status` | AdminScanStatus | Admin | Domain scan monitoring |
| `/admin/cyberpanel` | AdminCyberPanel | Admin | CyberPanel server and account management |

---

# API Reference

All API paths are prefixed with `/api` and return JSON. Protected endpoints require a JWT token in the `Authorization` header:

```
Authorization: Bearer <token>
```

## Public Endpoints (No Authentication)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/api/public/site-config` | Get public site configuration |
| GET | `/api/public/root-domains` | List available root domains |
| GET | `/api/public/announcements` | List published announcements |
| GET | `/api/public/announcements/:id` | Get a single announcement |
| GET | `/api/public/domain-health` | List health status of all domains |
| GET | `/api/public/domain-health/:domainId` | Get health summary for a domain |
| GET | `/api/public/domain-health/:domainId/scans` | Get scan history for a domain |
| GET | `/api/public/health-statistics` | Get platform-wide scan statistics |
| GET | `/api/public/pages` | List published custom pages |
| GET | `/api/public/pages/:slug` | Get a page by slug |
| GET | `/api/public/pending-domains` | List pending (pre-reserved) domains |
| GET | `/api/public/whois/:domain` | WHOIS lookup |
| GET | `/api/payments/callback` | NodeLoc payment callback (signature-verified) |
| GET | `/api/payments/return` | Payment return redirect |

## Authentication Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Register with email and optional invite code |
| POST | `/api/auth/login` | Login, returns JWT |
| GET | `/api/auth/github` | Initiate GitHub OAuth |
| GET | `/api/auth/github/callback` | GitHub OAuth callback |
| GET | `/api/auth/google` | Initiate Google OAuth |
| GET | `/api/auth/google/callback` | Google OAuth callback |
| GET | `/api/auth/nodeloc` | Initiate NodeLoc OAuth |
| GET | `/api/auth/nodeloc/callback` | NodeLoc OAuth callback |

## User Endpoints (JWT Required)

| Method | Path | Description |
|---|---|---|
| GET | `/api/user/profile` | Get own profile |
| PUT | `/api/user/profile` | Update profile |
| PUT | `/api/user/change-password` | Change password |

## Domain Endpoints (JWT Required)

| Method | Path | Description |
|---|---|---|
| GET | `/api/domains/search` | Check subdomain availability |
| POST | `/api/domains` | Register a domain |
| GET | `/api/domains` | List my domains |
| GET | `/api/domains/:id` | Get domain detail |
| DELETE | `/api/domains/:id` | Delete a domain |
| PUT | `/api/domains/:id/nameservers` | Update nameservers |
| POST | `/api/domains/:id/renew` | Renew a domain |
| POST | `/api/domains/:id/transfer` | Transfer a domain |
| GET | `/api/domains/:id/dnssec` | Get DNSSEC info |
| POST | `/api/domains/:id/dnssec/enable` | Enable DNSSEC |
| POST | `/api/domains/:id/dnssec/disable` | Disable DNSSEC |
| POST | `/api/domains/:id/dnssec/publish-ds` | Publish DS records to the parent zone. Yunamo nameservers: no body (DS comes from the signed zone). Custom nameservers: `{"ds_records": ["<key tag> <algorithm> <digest type> <digest>"]}`, which replaces the published DS set; algorithms 8/10/13/14/15/16, digest type 2 or 4 |
| GET | `/api/domain-scans/:id` | Get scan records for a domain |

## DNS Record Endpoints (JWT Required)

| Method | Path | Description |
|---|---|---|
| GET | `/api/dns/:domainId/records` | List DNS records |
| POST | `/api/dns/:domainId/records` | Create a DNS record |
| POST | `/api/dns/:domainId/records/sync-from-powerdns` | Sync records from PowerDNS |
| GET | `/api/dns/:domainId/records/:recordId` | Get a single record |
| PUT | `/api/dns/:domainId/records/:recordId` | Update a DNS record |
| DELETE | `/api/dns/:domainId/records/:recordId` | Delete a DNS record |

## Orders & Payments Endpoints (JWT Required)

| Method | Path | Description |
|---|---|---|
| POST | `/api/coupons/apply` | Apply a coupon |
| GET | `/api/coupons/my-usage` | My coupon usage history |
| GET | `/api/invitations/my` | My invitation list |
| GET | `/api/invitations/stats` | Invitation statistics |
| POST | `/api/orders/calculate` | Preview price with coupon |
| POST | `/api/orders` | Create an order |
| GET | `/api/orders` | List my orders |
| GET | `/api/orders/:id` | Get order detail |
| POST | `/api/orders/:id/cancel` | Cancel an order |
| POST | `/api/payments/:orderId/initiate` | Start payment, get redirect URL |
| POST | `/api/payments/:orderId/complete-free` | Complete a free (₀) order |
| GET | `/api/payments/:orderId/status` | Query payment status |

## CyberPanel Hosting Endpoints (JWT Required)

| Method | Path | Description |
|---|---|---|
| GET | `/api/cyberpanel/servers` | List available hosting servers |
| GET | `/api/cyberpanel/accounts` | List my hosting accounts |
| POST | `/api/cyberpanel/accounts` | Create a hosting account |
| GET | `/api/cyberpanel/accounts/:id/credentials` | Get account credentials |
| GET | `/api/cyberpanel/accounts/:id/autologin` | Auto-login to CyberPanel |
| DELETE | `/api/cyberpanel/accounts/:id` | Delete a hosting account |

## Admin Endpoints (JWT + Admin Flag Required)

| Group | Capabilities |
|---|---|
| Settings | GET/PUT system settings, system info, dashboard stats, clear Redis cache |
| Users | List, update, enable/disable, delete |
| Domains | List all with stats, update status, delete |
| Root Domains | Full CRUD; DNSSEC status/enable/disable for the root zone (`GET /api/admin/root-domains/:id/dnssec`, `POST .../dnssec/enable`, `POST .../dnssec/disable`); bulk delegation repair (`POST .../dnssec/repair`); orphan zone scan/cleanup (`GET .../orphan-zones`, `POST .../orphan-zones/cleanup`) |
| Coupons | Full CRUD |
| Announcements | Full CRUD |
| Custom Pages | Full CRUD |
| Orders | View all orders |
| Scans | View API quotas, scan summaries, suspend history |
| CyberPanel Servers | Full CRUD, test connection, admin auto-login |
| CyberPanel Accounts | List all, suspend/unsuspend, terminate |

---

# FAQ

**Q: How do I register a domain?**
Search for an available subdomain on the home page. Select a root domain and proceed to checkout. Free domains are activated immediately. Paid domains are activated after payment is completed via NodeLoc.

**Q: What DNS record types are supported?**
A, AAAA, CNAME, ALIAS, MX, TXT, NS, SRV, and CAA — 9 types in total. All changes sync in real time to PowerDNS.

**Q: What does the "DNS not synced" warning mean?**
The DNS records exist in the local database but have not been successfully pushed to PowerDNS. You can trigger a manual sync from the DNS management page.

**Q: Why was my domain suspended?**
Common reasons include:
- Repeated health scan failures (HTTP unreachable, SSL certificate expired, Google Safe Browsing or VirusTotal flags)
- Violation of the platform's terms of use

Click the `suspended` badge on the domain card to view the reason. Contact the administrator to appeal.

**Q: What does the pending deletion warning mean?**
When a domain remains in a failed state beyond the configured grace period, a countdown appears on the domain card. Renew the domain or fix the underlying issue before the timer expires.

**Q: How do I enable DNSSEC?**
Open the domain detail page, navigate to the DNSSEC section, and click Enable. The system generates a signing key for your zone and publishes the DS record into the parent (root domain) zone automatically. The DNSSEC panel shows whether the parent zone is signed and whether the DS is in place; the chain of trust is only complete when both are true. Domains that use custom nameservers are signed at their nameserver provider: enable DNSSEC there, then paste the DS record(s) the provider shows (for example `4515 13 2 6F67…`) into the DNSSEC panel on the domain page and click Publish. A DS that does not match the provider's keys makes the domain fail on validating resolvers, so copy it exactly; Remove DS takes it out of the parent zone again. Changing to different custom nameservers removes the published DS, since it belongs to the old provider's keys.

**Q: What happens to DNS when a domain is suspended?**
A suspended domain stops resolving: every record in its zone is disabled (the zone answers NODATA), legacy records in the parent zone are disabled, and for custom-nameserver domains the NS delegation in the parent is disabled (NXDOMAIN). Nothing is deleted, so reactivation restores the previous records. Health scans of suspended domains connect directly to the address stored in the domain's records (or answered by its custom nameservers), so a domain that has been fixed is still detected and restored automatically.

**Q: Why does DNSSEC show "chain of trust incomplete"? (administrators)**
Subdomain DNSSEC only validates when the root domain itself is signed and its DS record is published at the registrar. In Admin → Root Domains, open the DNSSEC dialog for the root domain, enable DNSSEC, and add the displayed DS record(s) at your registrar. Before disabling DNSSEC on a root domain, remove the DS at the registrar first and wait for its TTL to expire.

**Q: What is an ALIAS record?**
An ALIAS record is a special variant of CNAME that can be used at the zone apex (root domain). PowerDNS resolves the target and returns the resulting IP to the client.

**Q: What coupon types are available?**
- **Percentage discount** — reduces the price by a given percentage
- **Fixed discount** — deducts a fixed amount from the price
- **Quota increase** — increases the number of domains you can register

**Q: How does the invitation reward work?**
When a user registers using your invitation code, both parties receive a reward configured by the administrator (typically a quota increase or level upgrade).

**Q: Can I log in with a third-party account?**
Yes. The login page supports GitHub, Google, and NodeLoc OAuth. The first OAuth login automatically creates an account. You can link or unlink providers from your profile page.

**Q: Is an invitation code required to register?**
It depends on the administrator's configuration. If the platform is running in invite-only mode, a valid invitation code is required to create an account.

**Q: What happens to DNS management when I change nameservers?**
If you update a domain's nameservers to a third-party provider, the platform's DNS management panel will be disabled. Because PowerDNS no longer controls resolution for that domain, record editing is locked until you switch back to the default nameservers.

**Q: How often are domain health scans run?**
Scans are executed by a background worker at a frequency configured by the administrator. Google Safe Browsing and VirusTotal integrations are subject to daily API quota limits visible in the admin panel.

---

# Support

## Contact

If you need assistance, use the following channels:

- **Announcements** — Check the platform announcements page for the latest news and maintenance notices.
- **Administrator** — Contact the platform administrator through the official channel.

## Reporting an Issue

When submitting a report, include the following to help with faster resolution:

1. Your username or registered email address
2. The domain name involved (if applicable)
3. A description of the steps you took
4. Any error messages or screenshots
5. The approximate time the issue occurred

## Self-Service Troubleshooting

### Domain not resolving
1. Verify that DNS records are correctly configured (A/CNAME pointing to the correct IP).
2. Check that the domain status is `active`.
3. Check the DNS sync status — if it shows "not synced", trigger a manual sync on the DNS management page.
4. Allow time for DNS propagation (up to 24–48 hours).

### Unable to log in
1. Confirm your email and password are correct.
2. Try logging in via OAuth (GitHub, Google, or NodeLoc).
3. Clear browser cache and cookies, then try again.

### Payment failed
1. Confirm your NodeLoc account has sufficient balance.
2. Check your network connection and re-initiate the payment.
3. Cancel the existing order and create a new one if needed.

### Domain suspended
1. Click the `suspended` badge on the domain card to view the suspension reason.
2. Resolve the underlying issue (e.g., restore HTTP reachability, renew the SSL certificate).
3. Contact the administrator to request unsuspension.

## Administrator Contact

For account level upgrades, special quota requests, or abuse appeals, contact the administrator through the official platform channel and provide relevant supporting information.
