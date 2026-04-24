const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');

require('dotenv').config({ path: path.resolve(process.cwd(), 'server/.env') });

const PORT = Number(process.env.PORT || 8787);
const JWT_SECRET = String(process.env.JWT_SECRET || '').trim();
const JWT_EXPIRES_IN = String(process.env.JWT_EXPIRES_IN || '7d').trim();
const DB_PATH = path.resolve(
    process.cwd(),
    String(process.env.DB_PATH || 'server/database.sqlite').trim()
);
const SCHEMA_PATH = path.resolve(process.cwd(), 'server/schema.sql');
const DEFAULT_FAMILY_PROFILE_ID = 'self';
const PASSWORD_HASH_PREFIX = 'sha256:';
const LEGACY_HASH_PREFIX = 'legacy:';

const CORS_ORIGINS = String(process.env.CORS_ORIGINS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
const LOCAL_ORIGIN_HOSTS = new Set(['localhost', '127.0.0.1']);

class PublicError extends Error {
    constructor(message, status = 400, extra = {}) {
        super(message);
        this.status = status;
        this.extra = extra;
    }
}

function safeJsonParse(value, fallback) {
    try {
        if (value === undefined || value === null || value === '') return fallback;
        return JSON.parse(value);
    } catch {
        return fallback;
    }
}

function safeJsonStringify(value, fallback = '{}') {
    try {
        return JSON.stringify(value);
    } catch {
        return fallback;
    }
}

function sanitizeEmail(value) {
    return String(value || '').trim().toLowerCase();
}

function sanitizeNickname(value) {
    return String(value || '').trim();
}

function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateNickname(nickname) {
    if (nickname.length < 3) {
        return 'Никнейм должен быть не короче 3 символов';
    }
    if (nickname.length > 32) {
        return 'Никнейм должен быть не длиннее 32 символов';
    }
    if (!/^[\p{L}\p{N}][\p{L}\p{N} ._-]*[\p{L}\p{N}]$/u.test(nickname)) {
        return 'Никнейм содержит недопустимые символы';
    }
    return null;
}

function hashPasswordPlain(password) {
    const digest = crypto.createHash('sha256').update(String(password || ''), 'utf8').digest('hex');
    return `${PASSWORD_HASH_PREFIX}${digest}`;
}

function normalizePasswordHashInput(passwordHash) {
    const normalized = String(passwordHash || '').trim();
    if (normalized.startsWith(PASSWORD_HASH_PREFIX) || normalized.startsWith(LEGACY_HASH_PREFIX)) {
        return normalized;
    }
    if (/^[a-f0-9]{64}$/i.test(normalized)) {
        return `${PASSWORD_HASH_PREFIX}${normalized.toLowerCase()}`;
    }
    return '';
}

function verifyPassword(password, storedHash) {
    const normalizedStored = String(storedHash || '').trim();
    if (!normalizedStored) return false;
    if (normalizedStored.startsWith(PASSWORD_HASH_PREFIX)) {
        return hashPasswordPlain(password) === normalizedStored;
    }

    const legacyBase64 = Buffer.from(String(password || ''), 'utf8').toString('base64');
    if (normalizedStored.startsWith(LEGACY_HASH_PREFIX)) {
        return normalizedStored === `${LEGACY_HASH_PREFIX}${legacyBase64}`;
    }
    return normalizedStored === legacyBase64;
}

function clonePlainObject(value, fallback = {}) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return fallback;
    return { ...value };
}

function sanitizeTelegramSettings(rawValue) {
    const raw = clonePlainObject(rawValue, {});
    const recipients = Array.isArray(raw.recipients)
        ? raw.recipients
        : String(raw.recipientsText || '')
            .split(/[,\s;]+/)
            .map((item) => String(item || '').trim())
            .filter(Boolean);

    return {
        enabled: raw.enabled === true || raw.enabled === 'enabled' || raw.enabled === 'on',
        hasToken: Boolean(raw.hasToken),
        recipients: [...new Set(recipients.map((item) => String(item || '').trim()).filter(Boolean))].slice(0, 12),
        alertState: clonePlainObject(raw.alertState, {}),
        emergencyState: clonePlainObject(raw.emergencyState, {}),
        lastError: String(raw.lastError || '').slice(0, 220),
        lastUpdatedAt: Number(raw.lastUpdatedAt) || 0
    };
}

function sanitizeSettingsForStorage(rawValue) {
    const settings = clonePlainObject(rawValue, {});
    if (settings.telegramCare && typeof settings.telegramCare === 'object') {
        settings.telegramCare = sanitizeTelegramSettings(settings.telegramCare);
    }
    return settings;
}

function normalizeGamification(rawValue) {
    const raw = clonePlainObject(rawValue, {});
    const achievements = Array.isArray(raw.unlockedAchievements)
        ? [...new Set(raw.unlockedAchievements.map((item) => String(item || '').trim()).filter(Boolean))]
        : Array.isArray(raw.achievements)
            ? [...new Set(raw.achievements.map((item) => String(item || '').trim()).filter(Boolean))]
            : [];
    const customizations = Array.isArray(raw.unlockedCustomizations)
        ? [...new Set(raw.unlockedCustomizations.map((item) => String(item || '').trim()).filter(Boolean))]
        : Array.isArray(raw.customizations)
            ? [...new Set(raw.customizations.map((item) => String(item || '').trim()).filter(Boolean))]
            : [];

    return {
        coins: Math.max(0, Math.floor(Number(raw.coins) || 0)),
        loginStreak: Math.max(0, Math.floor(Number(raw.loginStreak) || 0)),
        bestLoginStreak: Math.max(0, Math.floor(Number(raw.bestLoginStreak) || 0)),
        lastLoginRewardDay: String(raw.lastLoginRewardDay || ''),
        unlockedAchievements: achievements,
        unlockedCustomizations: customizations,
        activeCustomization: String(raw.activeCustomization || '')
    };
}

function ensureDefaultFamilyState(userNickname, familyState, fallbackMedicines = []) {
    const safeFamily = clonePlainObject(familyState, {});
    const profiles = Array.isArray(safeFamily.profiles) ? safeFamily.profiles : [];
    const medicinesByProfile = clonePlainObject(safeFamily.medicinesByProfile, {});
    const normalizedProfiles = [];

    const selfProfile = profiles.find(
        (profile) => String(profile?.id || '').trim() === DEFAULT_FAMILY_PROFILE_ID
    ) || {};

    normalizedProfiles.push({
        id: DEFAULT_FAMILY_PROFILE_ID,
        name: String(selfProfile.name || userNickname || 'Я').trim() || 'Я',
        relation: String(selfProfile.relation || 'Я').trim() || 'Я',
        createdAt:
            typeof selfProfile.createdAt === 'string' && selfProfile.createdAt
                ? selfProfile.createdAt
                : new Date().toISOString()
    });

    for (const profile of profiles) {
        const profileId = String(profile?.id || '').trim();
        if (!profileId || profileId === DEFAULT_FAMILY_PROFILE_ID) continue;
        if (normalizedProfiles.some((item) => item.id === profileId)) continue;

        normalizedProfiles.push({
            id: profileId,
            name: String(profile?.name || 'Участник семьи').trim() || 'Участник семьи',
            relation: String(profile?.relation || 'Семья').trim() || 'Семья',
            createdAt:
                typeof profile?.createdAt === 'string' && profile.createdAt
                    ? profile.createdAt
                    : new Date().toISOString()
        });
    }

    const nextMedicinesByProfile = {};
    for (const profile of normalizedProfiles) {
        nextMedicinesByProfile[profile.id] = Array.isArray(medicinesByProfile[profile.id])
            ? medicinesByProfile[profile.id]
            : [];
    }

    const hasAnyFamilyMedicines = Object.values(nextMedicinesByProfile).some(
        (items) => Array.isArray(items) && items.length > 0
    );
    if (!hasAnyFamilyMedicines && Array.isArray(fallbackMedicines) && fallbackMedicines.length > 0) {
        nextMedicinesByProfile[DEFAULT_FAMILY_PROFILE_ID] = fallbackMedicines;
    }

    const activeProfileId = normalizedProfiles.some(
        (profile) => profile.id === safeFamily.activeProfileId
    )
        ? safeFamily.activeProfileId
        : DEFAULT_FAMILY_PROFILE_ID;

    return {
        profiles: normalizedProfiles,
        activeProfileId,
        medicinesByProfile: nextMedicinesByProfile
    };
}

async function createDb() {
    if (!JWT_SECRET) {
        throw new Error('JWT_SECRET is required in server/.env');
    }
    if (!fs.existsSync(SCHEMA_PATH)) {
        throw new Error(`Schema file not found: ${SCHEMA_PATH}`);
    }

    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    const db = await open({
        filename: DB_PATH,
        driver: sqlite3.Database
    });
    await db.exec('PRAGMA foreign_keys = ON;');
    await db.exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));
    return db;
}

const dbPromise = createDb();

async function getUserRowByEmail(email) {
    const db = await dbPromise;
    return db.get('SELECT * FROM users WHERE email = ?', email);
}

async function getUserRowById(id) {
    const db = await dbPromise;
    return db.get('SELECT * FROM users WHERE id = ?', id);
}

async function loadUserState(userId) {
    const db = await dbPromise;
    const user = await getUserRowById(userId);
    if (!user) return null;

    const medicinesRow = await db.get('SELECT medicine_data FROM user_medicines WHERE user_id = ?', userId);
    const gamificationRow = await db.get('SELECT * FROM user_gamification WHERE user_id = ?', userId);
    const familyRows = await db.all(
        'SELECT profile_key, profile_name, relation, medicines, created_at FROM family_profiles WHERE user_id = ? ORDER BY id',
        userId
    );

    const medicines = safeJsonParse(medicinesRow?.medicine_data, []);
    const settings = sanitizeSettingsForStorage(safeJsonParse(user.settings, {}));
    const avatar = safeJsonParse(user.avatar, null);

    const gamification = normalizeGamification({
        coins: gamificationRow?.coins,
        loginStreak: gamificationRow?.login_streak,
        bestLoginStreak: gamificationRow?.best_login_streak,
        lastLoginRewardDay: gamificationRow?.last_login_reward_day,
        unlockedAchievements: safeJsonParse(gamificationRow?.achievements, []),
        unlockedCustomizations: safeJsonParse(gamificationRow?.customizations, []),
        activeCustomization: gamificationRow?.active_customization
    });

    const familyProfiles = familyRows.map((row) => ({
        id: String(row.profile_key || '').trim(),
        name: String(row.profile_name || '').trim() || 'Профиль',
        relation: String(row.relation || '').trim(),
        createdAt: row.created_at || new Date().toISOString()
    }));

    const familyMedicinesByProfile = {};
    for (const row of familyRows) {
        const profileKey = String(row.profile_key || '').trim();
        if (!profileKey) continue;
        familyMedicinesByProfile[profileKey] = safeJsonParse(row.medicines, []);
    }

    const family = ensureDefaultFamilyState(
        user.nickname,
        {
            profiles: familyProfiles,
            activeProfileId: settings?.family?.activeProfileId || DEFAULT_FAMILY_PROFILE_ID,
            medicinesByProfile: familyMedicinesByProfile
        },
        medicines
    );

    return {
        id: user.id,
        email: user.email,
        name: user.nickname,
        nickname: user.nickname,
        createdAt: user.created_at,
        avatar,
        settings,
        medicines: Array.isArray(medicines) ? medicines : [],
        gamification,
        family
    };
}

async function upsertUserMedicines(userId, medicines) {
    const db = await dbPromise;
    const safeMedicines = Array.isArray(medicines) ? medicines : [];
    await db.run(
        `
        INSERT INTO user_medicines (user_id, medicine_data, updated_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(user_id) DO UPDATE SET
            medicine_data = excluded.medicine_data,
            updated_at = datetime('now')
        `,
        userId,
        safeJsonStringify(safeMedicines, '[]')
    );
}

async function upsertUserGamification(userId, rawGamification) {
    const db = await dbPromise;
    const gamification = normalizeGamification(rawGamification);
    await db.run(
        `
        INSERT INTO user_gamification (
            user_id, coins, login_streak, achievements, customizations,
            best_login_streak, last_login_reward_day, active_customization, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(user_id) DO UPDATE SET
            coins = excluded.coins,
            login_streak = excluded.login_streak,
            achievements = excluded.achievements,
            customizations = excluded.customizations,
            best_login_streak = excluded.best_login_streak,
            last_login_reward_day = excluded.last_login_reward_day,
            active_customization = excluded.active_customization,
            updated_at = datetime('now')
        `,
        userId,
        gamification.coins,
        gamification.loginStreak,
        safeJsonStringify(gamification.unlockedAchievements, '[]'),
        safeJsonStringify(gamification.unlockedCustomizations, '[]'),
        gamification.bestLoginStreak,
        gamification.lastLoginRewardDay,
        gamification.activeCustomization
    );
}

async function replaceFamilyProfiles(userId, familyState, fallbackNickname, fallbackMedicines) {
    const db = await dbPromise;
    const safeFamilyState = ensureDefaultFamilyState(fallbackNickname, familyState, fallbackMedicines);

    await db.run('DELETE FROM family_profiles WHERE user_id = ?', userId);
    for (const profile of safeFamilyState.profiles) {
        const profileId = String(profile.id || '').trim();
        if (!profileId) continue;
        await db.run(
            `
            INSERT INTO family_profiles (user_id, profile_key, profile_name, relation, medicines, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            `,
            userId,
            profileId,
            String(profile.name || 'Профиль').trim() || 'Профиль',
            String(profile.relation || '').trim(),
            safeJsonStringify(safeFamilyState.medicinesByProfile[profileId] || [], '[]'),
            profile.createdAt || new Date().toISOString()
        );
    }

    return safeFamilyState;
}

async function applyUserSync(userId, payload = {}) {
    const db = await dbPromise;
    const currentUser = await getUserRowById(userId);
    if (!currentUser) throw new PublicError('Пользователь не найден', 404);

    const existingSettings = sanitizeSettingsForStorage(safeJsonParse(currentUser.settings, {}));
    let nextSettings = { ...existingSettings };
    if (payload.settings && typeof payload.settings === 'object') {
        nextSettings = {
            ...existingSettings,
            ...sanitizeSettingsForStorage(payload.settings)
        };
    }

    const nextNickname = sanitizeNickname(payload.nickname || currentUser.nickname);
    const nextAvatar = Object.prototype.hasOwnProperty.call(payload, 'avatar')
        ? payload.avatar
        : safeJsonParse(currentUser.avatar, null);

    await db.exec('BEGIN');
    try {
        await db.run(
            'UPDATE users SET nickname = ?, avatar = ?, settings = ? WHERE id = ?',
            nextNickname || currentUser.nickname,
            safeJsonStringify(nextAvatar, 'null'),
            safeJsonStringify(nextSettings, '{}'),
            userId
        );

        if (Object.prototype.hasOwnProperty.call(payload, 'medicines')) {
            await upsertUserMedicines(userId, payload.medicines);
        }
        if (payload.gamification && typeof payload.gamification === 'object') {
            await upsertUserGamification(userId, payload.gamification);
        }

        if (payload.family && typeof payload.family === 'object') {
            const safeFamily = await replaceFamilyProfiles(
                userId,
                payload.family,
                nextNickname || currentUser.nickname,
                Array.isArray(payload.medicines) ? payload.medicines : []
            );

            nextSettings = {
                ...nextSettings,
                family: {
                    ...(clonePlainObject(nextSettings.family, {})),
                    activeProfileId: safeFamily.activeProfileId
                }
            };
            await db.run(
                'UPDATE users SET settings = ? WHERE id = ?',
                safeJsonStringify(nextSettings, '{}'),
                userId
            );
        }

        await db.exec('COMMIT');
    } catch (error) {
        await db.exec('ROLLBACK');
        throw error;
    }

    return loadUserState(userId);
}

function isOriginAllowed(origin) {
    if (!origin || origin === 'null') return true;

    if (CORS_ORIGINS.length > 0) {
        return CORS_ORIGINS.includes(origin);
    }

    try {
        const url = new URL(origin);
        return LOCAL_ORIGIN_HOSTS.has(url.hostname);
    } catch {
        return false;
    }
}

const app = express();
app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
    const origin = String(req.headers.origin || '');
    const allowed = isOriginAllowed(origin);

    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

    if (allowed && origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }

    if (req.method === 'OPTIONS') {
        res.status(allowed ? 204 : 403).end();
        return;
    }
    if (!allowed && origin) {
        res.status(403).json({ ok: false, error: 'Origin is not allowed by CORS policy' });
        return;
    }

    next();
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: Number(process.env.AUTH_LIMIT_PER_15_MIN || 120),
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, error: 'Слишком много запросов. Попробуйте позже.' }
});

function sendPublicError(res, error) {
    if (error instanceof PublicError) {
        res.status(error.status).json({
            ok: false,
            error: error.message,
            ...(error.extra || {})
        });
        return;
    }
    console.error('[sqlite-server] unexpected error:', error);
    res.status(500).json({ ok: false, error: 'Внутренняя ошибка сервера' });
}

function requireAuth(req, _res, next) {
    try {
        const authHeader = String(req.headers.authorization || '');
        const token = authHeader.startsWith('Bearer ')
            ? authHeader.slice('Bearer '.length).trim()
            : '';
        if (!token) {
            throw new PublicError('Требуется авторизация', 401);
        }
        const decoded = jwt.verify(token, JWT_SECRET);
        req.auth = decoded;
        next();
    } catch (error) {
        next(error instanceof PublicError ? error : new PublicError('Недействительный токен', 401));
    }
}

app.get('/api/health', async (_req, res) => {
    try {
        await dbPromise;
        res.json({
            ok: true,
            service: 'sqlite-auth-server',
            dbPath: DB_PATH
        });
    } catch (error) {
        sendPublicError(res, error);
    }
});

app.post('/api/register', authLimiter, async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const nickname = sanitizeNickname(req.body?.nickname);
        const plainPassword = String(req.body?.password || '');
        const providedPasswordHash = normalizePasswordHashInput(req.body?.passwordHash);

        if (!email || !nickname) {
            throw new PublicError('Email и никнейм обязательны');
        }
        if (!validateEmail(email)) {
            throw new PublicError('Введите корректный email адрес');
        }
        const nicknameError = validateNickname(nickname);
        if (nicknameError) throw new PublicError(nicknameError);

        let passwordHash = providedPasswordHash;
        if (!passwordHash) {
            if (!plainPassword || plainPassword.length < 6) {
                throw new PublicError('Пароль обязателен (минимум 6 символов)');
            }
            passwordHash = hashPasswordPlain(plainPassword);
        }

        const existing = await getUserRowByEmail(email);
        if (existing) {
            throw new PublicError('Пользователь с таким email уже существует', 409);
        }

        const db = await dbPromise;
        await db.exec('BEGIN');
        try {
            const insertUser = await db.run(
                `
                INSERT INTO users (email, nickname, password_hash, avatar, settings)
                VALUES (?, ?, ?, 'null', ?)
                `,
                email,
                nickname,
                passwordHash,
                safeJsonStringify(
                    {
                        notifications: 'enabled',
                        theme: 'light',
                        family: { activeProfileId: DEFAULT_FAMILY_PROFILE_ID }
                    },
                    '{}'
                )
            );

            const userId = insertUser.lastID;
            await upsertUserMedicines(userId, []);
            await upsertUserGamification(userId, {});
            await replaceFamilyProfiles(
                userId,
                {
                    profiles: [{ id: DEFAULT_FAMILY_PROFILE_ID, name: 'Я', relation: 'Я' }],
                    activeProfileId: DEFAULT_FAMILY_PROFILE_ID,
                    medicinesByProfile: { [DEFAULT_FAMILY_PROFILE_ID]: [] }
                },
                nickname,
                []
            );

            await db.exec('COMMIT');
            const userState = await loadUserState(userId);
            res.status(201).json({
                ok: true,
                user: {
                    email: userState.email,
                    nickname: userState.nickname,
                    createdAt: userState.createdAt
                }
            });
        } catch (error) {
            await db.exec('ROLLBACK');
            throw error;
        }
    } catch (error) {
        sendPublicError(res, error);
    }
});

app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const plainPassword = String(req.body?.password || '');
        const passwordHash = normalizePasswordHashInput(req.body?.passwordHash);

        if (!email || (!plainPassword && !passwordHash)) {
            throw new PublicError('Email и пароль обязательны');
        }

        const user = await getUserRowByEmail(email);
        if (!user) {
            throw new PublicError('Пользователь не найден', 404);
        }

        const isValid = passwordHash
            ? user.password_hash === passwordHash
            : verifyPassword(plainPassword, user.password_hash);
        if (!isValid) {
            throw new PublicError('Неверный пароль', 401);
        }

        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );
        const userState = await loadUserState(user.id);

        res.json({
            ok: true,
            token,
            user: userState
        });
    } catch (error) {
        sendPublicError(res, error);
    }
});

app.get('/api/user/medicines', requireAuth, async (req, res) => {
    try {
        const userState = await loadUserState(req.auth.userId);
        if (!userState) throw new PublicError('Пользователь не найден', 404);

        res.json({
            ok: true,
            medicines: userState.medicines,
            family: userState.family,
            user: userState
        });
    } catch (error) {
        sendPublicError(res, error);
    }
});

app.post('/api/user/medicines', requireAuth, async (req, res) => {
    try {
        const userState = await applyUserSync(req.auth.userId, {
            medicines: Array.isArray(req.body?.medicines) ? req.body.medicines : [],
            family: req.body?.family && typeof req.body.family === 'object' ? req.body.family : undefined
        });
        res.json({
            ok: true,
            medicines: userState.medicines,
            family: userState.family,
            user: userState
        });
    } catch (error) {
        sendPublicError(res, error);
    }
});

app.post('/api/user/sync', requireAuth, async (req, res) => {
    try {
        const userState = await applyUserSync(req.auth.userId, {
            medicines: Array.isArray(req.body?.medicines) ? req.body.medicines : undefined,
            gamification: req.body?.gamification && typeof req.body.gamification === 'object'
                ? req.body.gamification
                : undefined,
            settings: req.body?.settings && typeof req.body.settings === 'object'
                ? req.body.settings
                : undefined,
            family: req.body?.family && typeof req.body.family === 'object'
                ? req.body.family
                : undefined,
            avatar: Object.prototype.hasOwnProperty.call(req.body || {}, 'avatar')
                ? req.body.avatar
                : undefined,
            nickname: Object.prototype.hasOwnProperty.call(req.body || {}, 'nickname')
                ? req.body.nickname
                : undefined
        });
        res.json({
            ok: true,
            user: userState
        });
    } catch (error) {
        sendPublicError(res, error);
    }
});

app.post('/api/user/backup', requireAuth, async (req, res) => {
    try {
        const db = await dbPromise;
        const userState = await loadUserState(req.auth.userId);
        if (!userState) throw new PublicError('Пользователь не найден', 404);

        const snapshot = {
            nickname: userState.nickname,
            avatar: userState.avatar,
            settings: userState.settings,
            medicines: userState.medicines,
            gamification: userState.gamification,
            family: userState.family
        };

        const result = await db.run(
            'INSERT INTO user_backups (user_id, snapshot_json) VALUES (?, ?)',
            req.auth.userId,
            safeJsonStringify(snapshot, '{}')
        );
        const backupRow = await db.get(
            'SELECT id, created_at FROM user_backups WHERE id = ?',
            result.lastID
        );

        res.json({
            ok: true,
            backup: {
                id: backupRow.id,
                createdAt: backupRow.created_at
            }
        });
    } catch (error) {
        sendPublicError(res, error);
    }
});

app.get('/api/user/backup/latest', requireAuth, async (req, res) => {
    try {
        const db = await dbPromise;
        const latestBackup = await db.get(
            `
            SELECT id, snapshot_json, created_at
            FROM user_backups
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 1
            `,
            req.auth.userId
        );
        if (!latestBackup) {
            throw new PublicError('Бэкап не найден', 404);
        }

        const snapshot = safeJsonParse(latestBackup.snapshot_json, {});
        const restoredUser = await applyUserSync(req.auth.userId, {
            medicines: snapshot.medicines,
            gamification: snapshot.gamification,
            settings: snapshot.settings,
            family: snapshot.family,
            avatar: snapshot.avatar,
            nickname: snapshot.nickname
        });

        res.json({
            ok: true,
            restoredAt: new Date().toISOString(),
            backup: {
                id: latestBackup.id,
                createdAt: latestBackup.created_at
            },
            user: restoredUser
        });
    } catch (error) {
        sendPublicError(res, error);
    }
});

function startServer() {
    const server = app.listen(PORT, () => {
        console.log(`[sqlite-server] started on http://localhost:${PORT}`);
        console.log(`[sqlite-server] DB: ${DB_PATH}`);
    });
    return server;
}

if (require.main === module) {
    startServer();
}

module.exports = {
    app,
    startServer,
    hashPasswordPlain,
    verifyPassword,
    sanitizeEmail,
    sanitizeNickname,
    validateEmail,
    validateNickname
};
