-- Remove is_admin field
ALTER TABLE users DROP COLUMN IF EXISTS is_admin;
