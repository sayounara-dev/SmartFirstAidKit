# Auth Mail Server

Минимальный backend для подтверждения регистрации по email.

## Быстрый запуск

1. Установите зависимости:

```bash
npm install
```

2. Создайте `server/.env` на основе `server/.env.example` и заполните SMTP-параметры.

3. Запустите сервер:

```bash
npm run auth-server
```

Сервер будет доступен на `http://localhost:8787`.

## API

- `GET /api/health` — проверка состояния сервера.
- `POST /api/auth/start-registration` — отправка кода:
    - body: `{ "email": "user@example.com", "nickname": "User123" }`
- `POST /api/auth/verify-registration` — проверка кода:
    - body: `{ "email": "user@example.com", "code": "123456" }`

## Безопасность

- Включены `helmet` и ограничение частоты запросов (`express-rate-limit`).
- CORS ограничивается переменной `CORS_ORIGINS`.
- Не храните реальные секреты в `server/.env.example` и не коммитьте `server/.env`.

## Gmail SMTP Setup

Сервер использует только SMTP (IMAP не нужен).

1. Включите 2-Step Verification в Google Account.
2. Создайте App Password для Mail.
3. Заполните `server/.env`:
   - `SMTP_HOST=smtp.gmail.com`
   - `SMTP_PORT=465`
   - `SMTP_SECURE=true`
   - `SMTP_USER=<your_gmail>@gmail.com`
   - `SMTP_PASS=<16-char-app-password>`
   - `SMTP_FROM=SmartAptechka <<your_gmail>@gmail.com>`

## Как это подключено во фронте

URL берётся из:

1. `window.SMART_APTECHKA_AUTH_API` (если задан),
2. `<meta name="smart-aptechka-auth-api" ...>`,
3. иначе `http://localhost:8787`.
