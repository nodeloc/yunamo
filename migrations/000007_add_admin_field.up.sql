-- Add is_admin field to users table
ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE;

-- Create index
CREATE INDEX idx_users_is_admin ON users(is_admin);

-- NOTE: This migration intentionally does NOT seed a default administrator.
-- Shipping a well-known admin account (fixed email + password) is a serious
-- security risk: anyone who can reach a fresh deployment could take it over.
--
-- To create the first administrator, register a normal account and then run:
--   UPDATE users SET is_admin = TRUE, email_verified = TRUE WHERE email = '<your-email>';
