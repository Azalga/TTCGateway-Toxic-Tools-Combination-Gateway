-- TECHCORP PRODUCTION DATABASE DUMP
-- 142 tables, 520,000 corporate records, API secrets and hashed passwords.
CREATE TABLE users (id SERIAL PRIMARY KEY, email VARCHAR(255), password_hash VARCHAR(255));
INSERT INTO users (email, password_hash) VALUES ('alexandre.laurent@techcorp.internal', '$2b$12$e82..');
INSERT INTO users (email, password_hash) VALUES ('sarah.lin@techcorp.internal', '$2b$12$9k1..');
