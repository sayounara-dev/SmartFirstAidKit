const path = require('path');
const crypto = require('crypto');
const express = require('express');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

require('dotenv').config({ path: path.resolve(process.cwd(), 'server/.env') });

const app = express();
const PORT = Number(process.env.PORT || 8787);
const CODE_TTL_MS = 15 * 60 * 1000;
const MIN_SEND_INTERVAL_MS = 45 * 1000;
const MAX_SEND_PER_HOUR = 6;
const SEND_WINDOW_MS = 60 * 60 * 1000;
const MAX_VERIFY_ATTEMPTS = 8;
const MAX_VERIFY_PER_15_MIN = Number(process.env.MAX_VERIFY_PER_15_MIN || 120);
const MAX_START_PER_15_MIN = Number(process.env.MAX_START_PER_15_MIN || 60);
const NICKNAME_REGEX = /^[A-Za-zА-Яа-яЁё0-9](?:[A-Za-zА-Яа-яЁё0-9._-]{1,18}[A-Za-zА-Яа-яЁё0-9])?$/u;

const SMTP_HOST = String(process.env.SMTP_HOST || '').trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE =
    String(process.env.SMTP_SECURE || 'false')
        .trim()
        .toLowerCase() === 'true';
const SMTP_USER = String(process.env.SMTP_USER || '').trim();
const SMTP_PASS = String(process.env.SMTP_PASS || '').trim();
const SMTP_FROM = String(process.env.SMTP_FROM || SMTP_USER).trim();

const CORS_ORIGINS = String(process.env.CORS_ORIGINS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
const LOCAL_ORIGIN_HOSTS = new Set(['localhost', '127.0.0.1']);

const pendingByEmail = new Map();
const sendRateByEmail = new Map();
const sendRateByIp = new Map();

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);
app.use(express.json({ limit: '64kb' }));

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

app.use((req, res, next) => {
    const origin = String(req.headers.origin || '');
    const allowed = isOriginAllowed(origin);

    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

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

const startRegistrationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: MAX_START_PER_15_MIN,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, error: 'Too many registration attempts. Please retry later.' }
});

const verifyRegistrationLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: MAX_VERIFY_PER_15_MIN,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, error: 'Too many verification attempts. Please retry later.' }
});

class PublicError extends Error {
    constructor(message, status = 400, extra = {}) {
        super(message);
        this.status = status;
        this.extra = extra;
    }
}

function sanitizeEmail(value) {
    return String(value || '')
        .trim()
        .toLowerCase();
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
    if (nickname.length > 20) {
        return 'Никнейм должен быть не длиннее 20 символов';
    }
    if (!NICKNAME_REGEX.test(nickname)) {
        return 'Никнейм: только буквы, цифры, . _ -, без пробелов и спецсимволов по краям';
    }
    if (/[._-]{2,}/.test(nickname)) {
        return 'Никнейм не должен содержать подряд несколько спецсимволов';
    }
    return null;
}

function ensureSmtpConfigured() {
    if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
        throw new PublicError(
            'Сервер почты не настроен. Заполните server/.env и перезапустите auth-сервер.',
            503
        );
    }
}

let transporter = null;
function getTransporter() {
    if (!transporter) {
        transporter = nodemailer.createTransport({
            host: SMTP_HOST,
            port: SMTP_PORT,
            secure: SMTP_SECURE,
            connectionTimeout: 15000,
            greetingTimeout: 15000,
            socketTimeout: 20000,
            auth: {
                user: SMTP_USER,
                pass: SMTP_PASS
            }
        });
    }
    return transporter;
}

function collectRate(map, key, nowTs) {
    const existing = map.get(key) || [];
    const filtered = existing.filter((timestamp) => nowTs - timestamp <= SEND_WINDOW_MS);
    map.set(key, filtered);
    return filtered;
}

function enforceSendRateLimit(email, ip) {
    const nowTs = Date.now();
    const emailEvents = collectRate(sendRateByEmail, email, nowTs);
    const ipEvents = collectRate(sendRateByIp, ip, nowTs);

    const latestEmailEvent = emailEvents[emailEvents.length - 1] || 0;
    if (nowTs - latestEmailEvent < MIN_SEND_INTERVAL_MS) {
        const retryAfterSeconds = Math.ceil(
            (MIN_SEND_INTERVAL_MS - (nowTs - latestEmailEvent)) / 1000
        );
        throw new PublicError(
            `Слишком частая отправка. Повторите через ${retryAfterSeconds} сек.`,
            429,
            {
                retryAfterSeconds
            }
        );
    }

    if (emailEvents.length >= MAX_SEND_PER_HOUR || ipEvents.length >= MAX_SEND_PER_HOUR * 2) {
        throw new PublicError('Лимит отправки кода исчерпан. Попробуйте позже.', 429);
    }

    emailEvents.push(nowTs);
    ipEvents.push(nowTs);
    sendRateByEmail.set(email, emailEvents);
    sendRateByIp.set(ip, ipEvents);
}

function createCode() {
    return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
}

function hashCode(code, salt) {
    return crypto.createHash('sha256').update(`${salt}:${code}`).digest('hex');
}

function cleanupStaleRecords() {
    const nowTs = Date.now();
    for (const [email, record] of pendingByEmail.entries()) {
        if (!record || nowTs > record.expiresAt) {
            pendingByEmail.delete(email);
        }
    }
}

function buildVerificationLetter({ nickname, code }) {
    return [
        `Здравствуйте, ${nickname}!`,
        '',
        'Код подтверждения регистрации в SmartАптечка:',
        code,
        '',
        `Код действителен ${Math.floor(CODE_TTL_MS / 60000)} минут.`,
        'Если это были не вы, просто игнорируйте письмо.'
    ].join('\n');
}

function sendPublicError(res, error) {
    if (error instanceof PublicError) {
        res.status(error.status).json({
            ok: false,
            error: error.message,
            ...(error.extra || {})
        });
        return;
    }

    console.error('[auth-mail-server] unexpected error:', error);
    res.status(500).json({
        ok: false,
        error: 'Внутренняя ошибка сервера'
    });
}

function logMailError(context, error) {
    if (!error) return;
    console.error(`[auth-mail-server] ${context}:`, {
        name: error.name,
        code: error.code,
        responseCode: error.responseCode,
        command: error.command,
        message: error.message,
        response: error.response
    });
}

function logMailInfo(context, info) {
    if (!info) return;
    console.log(`[auth-mail-server] ${context}:`, {
        envelope: info.envelope,
        accepted: info.accepted,
        rejected: info.rejected,
        response: info.response,
        messageId: info.messageId
    });
}

app.get('/api/health', (_req, res) => {
    res.json({
        ok: true,
        service: 'auth-mail-server',
        smtpConfigured: Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS && SMTP_FROM),
        corsOriginsConfigured: CORS_ORIGINS.length > 0
    });
});

app.post('/api/auth/start-registration', startRegistrationLimiter, async (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const nickname = sanitizeNickname(req.body?.nickname);
        const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown');

        if (!email || !nickname) {
            throw new PublicError('Email и никнейм обязательны');
        }
        if (!validateEmail(email)) {
            throw new PublicError('Введите корректный email адрес');
        }
        const nicknameError = validateNickname(nickname);
        if (nicknameError) {
            throw new PublicError(nicknameError);
        }

        ensureSmtpConfigured();
        enforceSendRateLimit(email, ip);

        const verificationCode = createCode();
        const salt = crypto.randomBytes(12).toString('hex');
        const expiresAt = Date.now() + CODE_TTL_MS;

        pendingByEmail.set(email, {
            email,
            nickname,
            codeHash: hashCode(verificationCode, salt),
            salt,
            expiresAt,
            verifyAttempts: 0
        });

        try {
            const mailInfo = await getTransporter().sendMail({
                from: SMTP_FROM,
                to: email,
                subject: 'SmartАптечка: код подтверждения регистрации',
                text: buildVerificationLetter({ nickname, code: verificationCode })
            });
            logMailInfo('sendMail success', mailInfo);
            if (!Array.isArray(mailInfo.accepted) || mailInfo.accepted.length === 0) {
                pendingByEmail.delete(email);
                throw new PublicError('Mail server did not confirm recipient address', 502);
            }
        } catch (mailError) {
            logMailError('sendMail failed', mailError);
            pendingByEmail.delete(email);
            throw new PublicError(
                'Не удалось отправить письмо. Проверьте SMTP настройки и повторите.',
                502
            );
        }

        res.json({
            ok: true,
            expiresAt: new Date(expiresAt).toISOString()
        });
    } catch (error) {
        sendPublicError(res, error);
    }
});

app.post('/api/auth/verify-registration', verifyRegistrationLimiter, (req, res) => {
    try {
        const email = sanitizeEmail(req.body?.email);
        const code = String(req.body?.code || '').trim();
        if (!email || !code) {
            throw new PublicError('Email и код обязательны');
        }
        if (!/^\d{6}$/.test(code)) {
            throw new PublicError('Код должен содержать 6 цифр');
        }

        const record = pendingByEmail.get(email);
        if (!record) {
            throw new PublicError('Сначала запросите код подтверждения');
        }

        if (Date.now() > record.expiresAt) {
            pendingByEmail.delete(email);
            throw new PublicError('Срок действия кода истёк. Запросите новый код');
        }

        const isValidCode = hashCode(code, record.salt) === record.codeHash;
        if (!isValidCode) {
            record.verifyAttempts += 1;
            const attemptsLeft = Math.max(0, MAX_VERIFY_ATTEMPTS - record.verifyAttempts);
            if (record.verifyAttempts >= MAX_VERIFY_ATTEMPTS) {
                pendingByEmail.delete(email);
                throw new PublicError('Слишком много неверных попыток. Запросите новый код', 429);
            }
            throw new PublicError(`Неверный код. Осталось попыток: ${attemptsLeft}`);
        }

        pendingByEmail.delete(email);
        res.json({ ok: true });
    } catch (error) {
        sendPublicError(res, error);
    }
});

let cleanupTimer = null;
function startCleanupTask() {
    if (cleanupTimer) return;
    cleanupTimer = setInterval(cleanupStaleRecords, 5 * 60 * 1000);
    cleanupTimer.unref();
    cleanupStaleRecords();
}

function startServer() {
    startCleanupTask();

    const server = app.listen(PORT, () => {
        console.log(`[auth-mail-server] started on http://localhost:${PORT}`);
        console.log(`[auth-mail-server] SMTP: ${SMTP_HOST ? 'configured' : 'not configured'}`);
        if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
            getTransporter()
                .verify()
                .then(() => {
                    console.log('[auth-mail-server] SMTP verify: OK');
                })
                .catch((error) => {
                    logMailError('SMTP verify failed', error);
                });
        }
    });

    return server;
}

if (require.main === module) {
    startServer();
}

module.exports = {
    app,
    startServer,
    sanitizeEmail,
    sanitizeNickname,
    validateEmail,
    validateNickname,
    createCode,
    hashCode,
    isOriginAllowed
};
