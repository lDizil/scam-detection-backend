-- Migration: Add role field to users table
-- This migration adds RBAC support to the existing users table

-- Add role column if it doesn't exist
ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user' NOT NULL;

-- Update existing users to have default role 'user'
UPDATE users SET role = 'user' WHERE role IS NULL OR role = '';

-- Create index for faster role-based queries
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Optional: Create a default admin user (change credentials!)
-- INSERT INTO users (username, email, password_hash, role, is_active, created_at, updated_at)
-- VALUES ('admin', 'admin@example.com', '$2a$10$...', 'admin', true, NOW(), NOW())
-- ON CONFLICT (username) DO NOTHING;
