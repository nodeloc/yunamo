<p align="center">
  <a href="https://yunamo.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="web/public/brand/yunamo-logo.svg">
      <img src="web/public/brand/yunamo-logo-on-light.svg" alt="Yunamo" height="56">
    </picture>
  </a>
</p>

<h1 align="center">Yunamo — your dynamo starts with a name</h1>

<p align="center">
  Free subdomains for developers, students and open-source communities.<br>
  <a href="https://yunamo.com"><strong>yunamo.com</strong></a> ·
  <a href="https://yunamo.com/pages/documentation">Docs</a> ·
  <a href="https://yunamo.com/status">Status</a> ·
  <a href="https://yunamo.com/sponsor">Sponsor</a> ·
  <a href="README.zh-CN.md">简体中文</a>
</p>

---

**Yunamo** (from *your dynamo*) runs a free, managed subdomain service. Claim a name, point it at any host or your own servers, and manage every DNS record yourself.

**Claim a name. Point it anywhere. Keep building.**

## Why Yunamo?

Getting a project online should not start with a bill.

- **Free subdomains** for side projects, portfolios, homelabs and open-source releases
- **Full DNS control**: A, AAAA, CNAME, MX, TXT, NS, SRV, CAA and more
- **DNSSEC** and **custom nameservers** when you need them
- **Bring any host**: your VPS, your homelab, or any hosting provider
- **Open source** and run in the open

## 🌍 Available domains

| Domain | Notes |
| --- | --- |
| **.nl8.eu** | Free |
| **.loc.cc** | Popular |
| **.rr.kg** | New |

More suffixes are on the way. The live list is always at [yunamo.com](https://yunamo.com).

## 🌐 DNS infrastructure

Yunamo zones are served by authoritative PowerDNS name servers:

- **ns1.nodelook.com**
- **ns2.nodelook.com**

Live uptime and incident history: [yunamo.com/status](https://yunamo.com/status)

## ❤️ Sponsors

Yunamo is free to use and is kept running by its sponsors and partners. Servers, bandwidth, DNS nodes and development time all cost something.

If you'd like to help, see **[yunamo.com/sponsor](https://yunamo.com/sponsor)**. To discuss contributing servers, bandwidth or domains, write to [support@yunamo.com](mailto:support@yunamo.com).

## 🚀 Get started

1. Sign up at **[yunamo.com](https://yunamo.com)** and verify your email.
2. Search for a name and claim it.
3. Add DNS records that point to your host.

- **Docs:** [yunamo.com/pages/documentation](https://yunamo.com/pages/documentation)
- **Community:** [Telegram @yunamo_official](https://t.me/yunamo_official)
- **Bugs and ideas:** [GitHub Issues](https://github.com/nodeloc/yunamo/issues)
- **Support:** [support@yunamo.com](mailto:support@yunamo.com)

## 🛡️ Acceptable use and abuse

Phishing, malware, spam and other abuse are not allowed. See the [acceptable use policy](https://yunamo.com/acceptable-use).

To report a domain, use [yunamo.com/report](https://yunamo.com/report) or email [support@yunamo.com](mailto:support@yunamo.com).

---

## 🧩 Features

- Domain claiming with live availability checks and renewals
- DNS record management (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA), DNSSEC, custom nameservers
- Sign in with email and password, GitHub, Google or NodeLoc
- Email verification, password reset and abuse report emails
- Coupons (quota, VIP, renewal), invitations and rewards
- Announcements, custom pages, sponsors, and a public status page
- Domain health scanning (DNS, HTTP, SSL and security checks)
- Admin console for users, domains, orders, sponsors and settings
- Telegram bot notifications

## 🛠️ Tech stack

- **Backend:** Go, Gin, PostgreSQL, Redis
- **Frontend:** Vue 3, Vite, Tailwind CSS, DaisyUI
- **DNS:** PowerDNS (MariaDB backend)
- **Deployment:** Docker Compose

## 📦 Self-hosting

You need Docker and Docker Compose.

```bash
git clone https://github.com/nodeloc/yunamo.git
cd yunamo

cp .env.example .env
# Change at least DB_PASSWORD, JWT_SECRET and POWERDNS_API_KEY.
# Set MAIL_* to send verification and password reset emails.

./docker-deploy.sh
```

To run the bundled PowerDNS as well, enable the `powerdns` profile:

```bash
# Also set PDNS_DB_PASSWORD and PDNS_ADMIN_SECRET in .env
docker compose --profile powerdns up -d
```

| Service | Address | Notes |
| --- | --- | --- |
| API backend | http://localhost:8000 | Always on |
| PowerDNS Admin | http://localhost:9191 | `powerdns` profile |
| PowerDNS API | http://localhost:8081 | `powerdns` profile |

`docker-compose.yml` runs these services:

- `postgres`: application database
- `redis`: cache and rate limits
- `migrate`: applies database migrations on every start
- `app`: the Yunamo backend, which also serves the frontend
- `pdns-db`, `powerdns`, `pdns-admin`: PowerDNS with MariaDB and its web UI (`powerdns` profile)

Common commands:

```bash
docker compose logs -f app   # follow the app logs
docker compose restart       # restart all services
docker compose down          # stop and remove containers
```

Notes:

- On Ubuntu, port 53 may be taken by `systemd-resolved`. Set `DNS_PORT=5353` in `.env` to use another port.
- The first time you open PowerDNS Admin (`:9191`), register an admin account and use `http://powerdns:8081` as the API URL.

## 🤝 Contributing

Issues and pull requests are welcome. Please open an issue first for larger changes.

## License

Released under the MIT License.

<p align="center"><sub>Yunamo · your dynamo</sub></p>
