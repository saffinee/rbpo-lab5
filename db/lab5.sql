-- Запуск для базы четвёртой лабораторной: psql -d parking_lab4 -f db/lab5.sql
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    device_id VARCHAR(255),
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL UNIQUE,
    access_token_expiry TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_token_expiry TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE', 'USED', 'REVOKED'))
);
GRANT SELECT, INSERT, UPDATE, DELETE ON user_sessions TO parking_lab4_app;
