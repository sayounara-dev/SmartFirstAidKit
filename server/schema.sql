PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    nickname TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    avatar TEXT NOT NULL DEFAULT 'null',
    settings TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS user_medicines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    medicine_data TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_gamification (
    user_id INTEGER PRIMARY KEY,
    coins INTEGER NOT NULL DEFAULT 0,
    login_streak INTEGER NOT NULL DEFAULT 0,
    achievements TEXT NOT NULL DEFAULT '[]',
    customizations TEXT NOT NULL DEFAULT '[]',
    best_login_streak INTEGER NOT NULL DEFAULT 0,
    last_login_reward_day TEXT NOT NULL DEFAULT '',
    active_customization TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS family_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    profile_key TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    relation TEXT NOT NULL DEFAULT '',
    medicines TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, profile_key),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    snapshot_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_medicines_user_id ON user_medicines(user_id);
CREATE INDEX IF NOT EXISTS idx_family_profiles_user_id ON family_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_backups_user_id_created_at ON user_backups(user_id, created_at DESC);
