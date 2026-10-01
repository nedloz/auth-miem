# Auth Service

Микросервис аутентификации и управления пользователями проекта «Автонаставник».

Сервис отвечает за:

* регистрацию и подтверждение электронной почты;
* авторизацию пользователей;
* access и refresh tokens;
* выход из системы и rotation refresh tokens;
* восстановление пароля;
* управление профилем пользователя;
* административные сессии;
* internal API для других микросервисов;
* отправку verification/reset писем через SMTP;
* краткоживущие auth-токены и кэш профилей через Redis.

---

## Архитектура

```text
                    ┌──────────────────┐
                    │     Frontend     │
                    └────────┬─────────┘
                             │
                             ▼
                         ┌───────┐
                         │ nginx │
                         └───┬───┘
                             │
                             ▼
                     ┌───────────────┐
                     │   auth-svc    │
                     └───────┬───────┘
                             │
               ┌─────────────┼─────────────┐
               │             │             │
               ▼             ▼             ▼
        ┌────────────┐ ┌────────────┐ ┌────────────┐
        │ PostgreSQL │ │   Redis    │ │    SMTP    │
        └────────────┘ └────────────┘ └────────────┘
```

PostgreSQL является основным хранилищем пользователей и состояния токенов.

Redis используется как дополнительный быстрый слой для:

* короткоживущих verification/reset tokens;
* кэширования профилей;
* временного состояния, которому не требуется постоянное хранение.

SMTP используется для отправки:

* писем подтверждения электронной почты;
* писем восстановления пароля.

---

# Основные endpoint'ы

## Аутентификация

| Метод  | Endpoint                    | Назначение                   |
| ------ | --------------------------- | ---------------------------- |
| `POST` | `/auth/register`            | Регистрация пользователя     |
| `POST` | `/auth/login`               | Авторизация                  |
| `POST` | `/auth/refresh`             | Обновление access token      |
| `POST` | `/auth/logout`              | Выход                        |
| `GET`  | `/auth/verify-email`        | Подтверждение email          |
| `POST` | `/auth/resend-verification` | Повторная отправка письма    |
| `POST` | `/auth/forgot-password`     | Запрос восстановления пароля |
| `POST` | `/auth/update-password`     | Установка нового пароля      |

## Проверка пользователя nginx

| Метод  | Endpoint                    | Назначение               |
| ------ | --------------------------- | ------------------------ |
| `GET`  | `/auth/validate`            | Проверка access JWT      |
| `POST` | `/auth/admin-session`       | Создание admin session   |
| `POST` | `/auth/admin-session/close` | Завершение admin session |
| `GET`  | `/auth/validate-admin`      | Проверка admin session   |

## Профиль

| Метод    | Endpoint    | Назначение               |
| -------- | ----------- | ------------------------ |
| `GET`    | `/users/me` | Получить текущий профиль |
| `PATCH`  | `/users/me` | Изменить профиль         |
| `DELETE` | `/users/me` | Деактивировать аккаунт   |

## Internal API

| Метод | Endpoint                            | Назначение                        |
| ----- | ----------------------------------- | --------------------------------- |
| `GET` | `/internal/users/{user_id}/profile` | Получение профиля другим сервисом |

Internal API используется другими микросервисами, например `chat-svc`.

---

# Хранение токенов

Токены генерируются через криптографически стойкий генератор случайных значений.

Raw token не сохраняется в PostgreSQL.

В PostgreSQL записывается только SHA-256 hash:

```text
raw token
    │
    ▼
 SHA-256
    │
    ▼
PostgreSQL
```

Например:

```text
email_verifications
├── user_id
├── token_hash
├── created_at
└── used_at
```

Для refresh token:

```text
refresh_tokens
├── user_id
├── token_hash
├── created_at
├── revoked_at
├── replaced_by_token_id
├── ip_address
└── user_agent
```

Для password reset:

```text
password_resets
├── user_id
├── token_hash
├── created_at
├── used_at
├── requested_ip
└── requested_user_agent
```

---

# Redis

Redis не заменяет PostgreSQL.

PostgreSQL остаётся источником истины, а Redis используется как быстрый временный слой.

## Verification token

```text
auth:token:verify:v1:<sha256>
```

TTL задаётся параметром:

```env
EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES
```

## Password reset token

```text
auth:token:reset:v1:<sha256>
```

TTL задаётся параметром:

```env
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
```

Если Redis недоступен или ключ отсутствует, сервис использует PostgreSQL.

Это означает, что отказ Redis не должен приводить к полной недоступности authentication.

---

# Кэш профилей

Профили пользователей кэшируются в Redis.

## Профиль `/users/me`

```text
auth:profile:me:v1:<user_id>
```

## Internal profile API

```text
auth:profile:internal:v1:<user_id>
```

TTL:

```env
PROFILE_CACHE_TTL_SECONDS=300
```

то есть по умолчанию 5 минут.

Алгоритм:

```text
GET /users/me
      │
      ▼
    Redis
      │
   ┌──┴──┐
 hit    miss
  │       │
  │       ▼
  │   PostgreSQL
  │       │
  └───────┘
      │
      ▼
   response
```

После изменения профиля Redis cache инвалидируется.

---

# SMTP

SMTP используется для отправки:

1. confirmation email;
2. password reset email.

Ссылки больше не выводятся в `stdout`.

Пример verification URL:

```text
https://example.com/verify-email?token=<token>
```

Пример reset URL:

```text
https://example.com/reset-password?token=<token>
```

---

# Настройка Gmail SMTP

Для Gmail можно использовать:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USE_SSL=false

SMTP_USER=example@gmail.com
SMTP_PASSWORD=<app-password>

EMAIL_FROM=example@gmail.com
```

Для SMTP authentication рекомендуется использовать пароль приложения, а не обычный пароль аккаунта.

---

# Переменные окружения

## Database

```env
DATABASE_URL=postgresql+asyncpg://user:password@postgres:5432/database
```

## JWT

```env
SECRET_KEY=change-me
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
```

## Token TTL

```env
REFRESH_TOKEN_EXPIRE_MINUTES=43200
EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES=1440
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES=60
```

По умолчанию:

| Токен              |      TTL |
| ------------------ | -------: |
| Access JWT         | 15 минут |
| Refresh token      |  30 дней |
| Email verification |  24 часа |
| Password reset     |    1 час |

## Frontend

```env
FRONTEND_BASE_URL=http://localhost
```

Этот URL используется для построения ссылок в email.

## SMTP

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587

SMTP_USER=
SMTP_PASSWORD=

SMTP_USE_TLS=true
SMTP_USE_SSL=false

EMAIL_FROM=
```

## Redis

```env
REDIS_URL=redis://redis:6379/0
PROFILE_CACHE_TTL_SECONDS=300
```

---

# Пример `.env`

```env
# PostgreSQL
DATABASE_URL=postgresql+asyncpg://auth_user:auth_password@postgres:5432/auth_db

# JWT
SECRET_KEY=replace-with-random-secret
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15

# Token TTL
REFRESH_TOKEN_EXPIRE_MINUTES=43200
EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES=1440
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES=60

# Frontend
FRONTEND_BASE_URL=http://localhost

# SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
SMTP_USE_SSL=false
EMAIL_FROM=your-email@gmail.com

# Redis
REDIS_URL=redis://redis:6379/0
PROFILE_CACHE_TTL_SECONDS=300
```

---

# Установка

Установить зависимости:

```bash
pip install -r requirements.txt
```

Основные зависимости:

```text
FastAPI
SQLAlchemy
asyncpg
bcrypt
PyJWT
pydantic-settings
redis
```

SMTP реализован через стандартную библиотеку Python `smtplib`, поэтому отдельная SMTP-библиотека не требуется.

---

# Локальный запуск

Заполнить `.env`, после чего:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Проверка:

```bash
curl http://localhost:8000/health
```

Ожидаемый ответ:

```json
{
  "status": "ok",
  "service": "auth"
}
```

---

# Docker

В общей инфраструктуре проекта `auth-svc` использует существующие PostgreSQL и Redis.

Redis подключается через:

```env
REDIS_URL=redis://redis:6379/0
```

Отдельный Redis специально для `auth-svc` не требуется.

---

# Взаимодействие с другими сервисами

## nginx

nginx выполняет JWT validation через:

```text
GET /auth/validate
```

После успешной проверки передаёт:

```text
X-User-Id
X-User-Role
```

в downstream-сервисы.

Для административного раздела используется:

```text
POST /auth/admin-session
GET  /auth/validate-admin
POST /auth/admin-session/close
```

## chat-svc

`chat-svc` может получать профиль пользователя через:

```text
GET /internal/users/{user_id}/profile
```

Доступ к internal API защищён service-to-service authentication.

Профиль дополнительно кэшируется в Redis.

## library-svc

`library-svc` не хранит собственные пользовательские auth-токены. Пользовательская авторизация выполняется через существующий gateway/auth flow.

---

# Безопасность

## Raw tokens

Raw verification/reset tokens:

* не сохраняются в PostgreSQL;
* не сохраняются в Redis;
* не выводятся в stdout.

В PostgreSQL и Redis используется только SHA-256 hash.

## Refresh tokens

Refresh token хранится в HttpOnly cookie.

При `/auth/refresh` выполняется rotation:

```text
old refresh token
       ↓
revoked
       ↓
new refresh token
```

Каждый refresh token имеет срок жизни из:

```env
REFRESH_TOKEN_EXPIRE_MINUTES
```

## One-time tokens

Verification и password-reset tokens являются одноразовыми.

После успешного использования:

```text
used_at = now()
```

и соответствующий Redis key удаляется.

---

# Изменение профиля и кэш

При:

```text
PATCH /users/me
```

данные сначала обновляются в PostgreSQL.

После успешного изменения cache профиля удаляется:

```text
PostgreSQL UPDATE
      ↓
Redis DELETE
```

Следующий запрос загрузит актуальный профиль из PostgreSQL и снова сохранит его в Redis.

---

# Поведение при отказе Redis

Redis является дополнительным cache/TTL-слоем.

Если Redis временно недоступен:

```text
Redis request
     ↓
ошибка
     ↓
PostgreSQL
```

Это позволяет сохранить работу основных authentication flows.

---

# Структура приложения

```text
app/
├── main.py
├── config.py
├── database.py
├── mail.py
├── models.py
├── redis.py
├── schemas.py
├── security.py
│
└── routers/
    ├── auth.py
    ├── profile.py
    └── internal.py
```

Назначение модулей:

| Файл                  | Назначение                          |
| --------------------- | ----------------------------------- |
| `main.py`             | FastAPI application и lifecycle     |
| `config.py`           | SMTP/Redis/TTL configuration        |
| `database.py`         | PostgreSQL                          |
| `mail.py`             | SMTP отправка                       |
| `redis.py`            | Redis cache и temporary state       |
| `models.py`           | SQLAlchemy models                   |
| `schemas.py`          | Pydantic schemas                    |
| `security.py`         | JWT/password/service authentication |
| `routers/auth.py`     | Authentication endpoints            |
| `routers/profile.py`  | User profile                        |
| `routers/internal.py` | Internal service API                |

---

# Проверка после запуска

## Health

```bash
curl http://localhost:8000/health
```

## Redis

Проверить контейнер Redis:

```bash
redis-cli ping
```

Ожидаемый ответ:

```text
PONG
```

Проверить auth keys:

```bash
redis-cli --scan --pattern 'auth:*'
```

Пример:

```text
auth:profile:me:v1:<user_id>
auth:profile:internal:v1:<user_id>
auth:token:verify:v1:<hash>
auth:token:reset:v1:<hash>
```

## SMTP

После регистрации:

```text
POST /auth/register
```

пользователь должен получить confirmation email.

После:

```text
POST /auth/forgot-password
```

пользователь должен получить password reset email.

Ссылки больше не должны появляться в stdout.

---

# Главное правило хранения данных

```text
PostgreSQL
    ↓
источник истины

Redis
    ↓
быстрый временный слой

SMTP
    ↓
доставка email
```

Redis не заменяет PostgreSQL и не используется для хранения долгоживущего состояния пользователя.
