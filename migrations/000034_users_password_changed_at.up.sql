-- 修改/重置密码后，签发时间早于该时间的 JWT 一律失效。
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
