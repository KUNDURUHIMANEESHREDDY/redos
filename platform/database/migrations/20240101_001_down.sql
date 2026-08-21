-- Migration down: 20240101_001_initial_schema.sql
-- Description: Drop all tables created in initial schema migration

DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS organization_members CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;
DROP TABLE IF EXISTS evidence CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS executions CASCADE;
DROP TABLE IF EXISTS attack_campaigns CASCADE;
DROP TABLE IF EXISTS targets CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
DROP TABLE IF EXISTS users CASCADE;

DROP EXTENSION IF EXISTS "uuid-ossp";