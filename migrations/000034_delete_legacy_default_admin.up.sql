-- Clean up the legacy default administrator created by older versions of
-- migration 000007 (admin@opendomain.local with a well-known password).
-- Fresh installs no longer seed it; this removes it from existing databases.
DELETE FROM users WHERE email = 'admin@opendomain.local' AND username = 'admin';
