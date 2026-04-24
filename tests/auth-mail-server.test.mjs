import { describe, it, expect } from 'vitest';
import authMailServer from '../server/auth-mail-server.js';

const { sanitizeEmail, validateEmail, validateNickname, createCode } = authMailServer;

describe('auth-mail-server helpers', () => {
    it('normalizes email before validation', () => {
        expect(sanitizeEmail('  USER@Example.com ')).toBe('user@example.com');
        expect(validateEmail('user@example.com')).toBe(true);
    });

    it('rejects invalid nickname by length', () => {
        const error = validateNickname('ab');
        expect(typeof error).toBe('string');
    });

    it('generates numeric 6-digit code', () => {
        const code = createCode();
        expect(code).toMatch(/^\d{6}$/);
    });
});
