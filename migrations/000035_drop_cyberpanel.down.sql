-- 恢复 000025 + 000026 之后的表结构（不含数据）。
CREATE TABLE IF NOT EXISTS cyberpanel_servers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    url VARCHAR(255) NOT NULL,
    admin_user VARCHAR(100) NOT NULL,
    admin_pass VARCHAR(512) NOT NULL,
    package_name VARCHAR(100) NOT NULL DEFAULT 'Default',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    max_accounts INT NOT NULL DEFAULT 0,
    current_accounts INT NOT NULL DEFAULT 0,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cyberpanel_accounts (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain_id INT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    server_id INT NOT NULL REFERENCES cyberpanel_servers(id) ON DELETE RESTRICT,
    cp_username VARCHAR(100) NOT NULL,
    cp_password VARCHAR(512) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_msg TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cyberpanel_accounts_user_id ON cyberpanel_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_cyberpanel_accounts_server_id ON cyberpanel_accounts(server_id);
