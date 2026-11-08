package handler

import (
	"context"
	"strconv"
	"time"

	"opendomain/pkg/logger"
)

// 登录失败限流：按 IP 与按账号（邮箱哈希）分别计数，只统计失败次数，
// 防止撞库和针对单个账号（尤其是管理员）的密码爆破。
const (
	loginFailIPLimit      = 30
	loginFailAccountLimit = 10
	loginFailWindow       = 15 * time.Minute
)

func loginFailIPKey(ip string) string { return "login:fail:ip:" + ip }

func loginFailAccountKey(email string) string {
	return "login:fail:account:" + hashEmailToken(normalizeEmail(email))
}

// loginBlocked reports whether the IP or the account has used up its failed
// attempts. It fails open when Redis is unavailable so an outage does not lock
// everyone out.
func (h *UserHandler) loginBlocked(ctx context.Context, ip, email string) bool {
	if h.rdb == nil {
		return false
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	vals, err := h.rdb.MGet(rctx, loginFailIPKey(ip), loginFailAccountKey(email)).Result()
	if err != nil {
		logger.Warnf("login rate limit: redis unavailable, allowing request: %v", err)
		return false
	}
	return counterAtLeast(vals[0], loginFailIPLimit) || counterAtLeast(vals[1], loginFailAccountLimit)
}

func counterAtLeast(v interface{}, limit int64) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return err == nil && n >= limit
}

// recordLoginFailure counts one failed attempt against both the IP and the account.
func (h *UserHandler) recordLoginFailure(ctx context.Context, ip, email string) {
	if h.rdb == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := incrRateWindow(rctx, h.rdb, loginFailIPKey(ip), loginFailWindow); err != nil {
		logger.Warnf("login rate limit: failed to record failure: %v", err)
		return
	}
	if _, err := incrRateWindow(rctx, h.rdb, loginFailAccountKey(email), loginFailWindow); err != nil {
		logger.Warnf("login rate limit: failed to record failure: %v", err)
	}
}

// clearLoginFailures resets the account counter after a successful login.
func (h *UserHandler) clearLoginFailures(ctx context.Context, email string) {
	if h.rdb == nil {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	h.rdb.Del(rctx, loginFailAccountKey(email))
}
