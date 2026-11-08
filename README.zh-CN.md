<p align="center">
  <a href="https://yunamo.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="web/public/brand/yunamo-logo.svg">
      <img src="web/public/brand/yunamo-logo-on-light.svg" alt="Yunamo" height="56">
    </picture>
  </a>
</p>

<h1 align="center">Yunamo：你的动力源，从一个名字开始</h1>

<p align="center">
  面向开发者、学生和开源社区的免费二级域名服务。<br>
  <a href="https://yunamo.com"><strong>yunamo.com</strong></a> ·
  <a href="https://yunamo.com/pages/documentation">文档</a> ·
  <a href="https://yunamo.com/status">服务状态</a> ·
  <a href="https://yunamo.com/sponsor">赞助</a> ·
  <a href="README.md">English</a>
</p>

---

**Yunamo** 取意于「your dynamo」，也就是你的动力源。我们提供免费、托管的二级域名服务：领取一个名字，指向任意主机或你自己的服务器，所有 DNS 记录由你掌控。

**领取一个名字，指向任何地方，继续创造。**

## 为什么选择 Yunamo？

把项目放上网络，不该从一张账单开始。

- **免费二级域名**：适合个人项目、作品集、家庭实验室和开源发布
- **完整的 DNS 控制**：A、AAAA、CNAME、MX、TXT、NS、SRV、CAA 等
- 需要时可启用 **DNSSEC** 和 **自定义 NS**
- **主机随你选**：VPS、家庭服务器或任意托管平台
- **开源**，公开运营

## 🌍 可用域名

| 域名 | 说明 |
| --- | --- |
| **.nl8.eu** | 免费 |
| **.loc.cc** | 热门 |
| **.rr.kg** | 新上线 |

更多后缀即将上线，实时列表请以 [yunamo.com](https://yunamo.com) 为准。

## 🌐 DNS 基础设施

Yunamo 的域名由 PowerDNS 权威名称服务器解析：

- **ns1.nodelook.com**
- **ns2.nodelook.com**

实时可用性与故障记录：[yunamo.com/status](https://yunamo.com/status)

## ❤️ 赞助

Yunamo 免费使用，靠赞助者和合作伙伴的支持持续运转。服务器、带宽、DNS 节点和开发时间都有成本。

如果你愿意支持我们，请访问 **[yunamo.com/sponsor](https://yunamo.com/sponsor)**。如果想提供服务器、带宽或域名等资源合作，请发邮件至 [support@yunamo.com](mailto:support@yunamo.com)。

## 🚀 开始使用

1. 在 **[yunamo.com](https://yunamo.com)** 注册并验证邮箱。
2. 搜索一个名字并领取。
3. 添加 DNS 记录，指向你的主机。

- **文档：** [yunamo.com/pages/documentation](https://yunamo.com/pages/documentation)
- **社区：** [Telegram @yunamo_official](https://t.me/yunamo_official)
- **问题反馈与建议：** [GitHub Issues](https://github.com/nodeloc/yunamo/issues)
- **支持邮箱：** [support@yunamo.com](mailto:support@yunamo.com)

## 🛡️ 使用规范与滥用举报

禁止钓鱼、恶意软件、垃圾邮件等滥用行为，详见 [可接受使用政策](https://yunamo.com/acceptable-use)。

举报域名请访问 [yunamo.com/report](https://yunamo.com/report)，或发送邮件至 [support@yunamo.com](mailto:support@yunamo.com)。

---

## 🧩 功能

- 域名领取，实时可用性查询与续期
- DNS 记录管理（A、AAAA、CNAME、MX、TXT、NS、SRV、CAA），DNSSEC，自定义 NS
- 邮箱密码、GitHub、Google、NodeLoc 登录
- 邮箱验证、找回密码、滥用举报邮件通知
- 优惠券（配额券、VIP 券、续期券）、邀请与奖励
- 公告、自定义页面、赞助者展示、公开状态页
- 域名健康扫描（DNS、HTTP、SSL、安全检测）
- 管理后台：用户、域名、订单、赞助者、系统设置
- Telegram Bot 通知

## 🛠️ 技术栈

- **后端：** Go、Gin、PostgreSQL、Redis
- **前端：** Vue 3、Vite、Tailwind CSS、DaisyUI
- **DNS：** PowerDNS（MariaDB 后端）
- **部署：** Docker Compose

## 📦 自行部署

需要 Docker 和 Docker Compose。

```bash
git clone https://github.com/nodeloc/yunamo.git
cd yunamo

cp .env.example .env
# 至少修改 DB_PASSWORD、JWT_SECRET、POWERDNS_API_KEY
# 如需发送验证邮件和找回密码邮件，请配置 MAIL_*

./docker-deploy.sh
```

如需同时启动内置 PowerDNS，使用 `powerdns` profile：

```bash
# 另需在 .env 中设置 PDNS_DB_PASSWORD、PDNS_ADMIN_SECRET
docker compose --profile powerdns up -d
```

| 服务 | 地址 | 说明 |
| --- | --- | --- |
| API 后端 | http://localhost:8000 | 默认启用 |
| PowerDNS Admin | http://localhost:9191 | 需启用 `powerdns` profile |
| PowerDNS API | http://localhost:8081 | 需启用 `powerdns` profile |

`docker-compose.yml` 包含以下服务：

- `postgres`：应用数据库
- `redis`：缓存与限流
- `migrate`：每次启动时自动执行数据库迁移
- `app`：Yunamo 后端，同时提供前端页面
- `pdns-db`、`powerdns`、`pdns-admin`：PowerDNS、MariaDB 及其管理面板（`powerdns` profile）

常用命令：

```bash
docker compose logs -f app   # 查看应用日志
docker compose restart       # 重启所有服务
docker compose down          # 停止并删除容器
```

注意事项：

- Ubuntu 上 53 端口可能被 `systemd-resolved` 占用，可在 `.env` 中设置 `DNS_PORT=5353` 改用其他端口。
- 首次访问 PowerDNS Admin（`:9191`）需注册管理员账号，API URL 填写 `http://powerdns:8081`。

## 🤝 参与贡献

欢迎提交 Issue 和 Pull Request。较大的改动请先开 Issue 讨论。

## 许可证

基于 MIT 许可证发布。

<p align="center"><sub>Yunamo · 你的动力源</sub></p>
