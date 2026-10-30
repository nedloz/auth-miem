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
| `POST`   | `/users/me/avatar` | Загрузить аватар (multipart, поле `file`; png, jpeg, webp, до 5 МБ) |
| `GET`    | `/users/me/avatar` | Картинка аватара (ETag, `Cache-Control: private`) |
| `DELETE` | `/users/me/avatar` | Сбросить аватар |

Все маршруты профиля и аватара, кроме входа и регистрации, требуют токен: nginx проверяет его через `auth_request`.
Поэтому `<img>` с `avatar_url` без заголовка `Authorization` не загрузит картинку, её надо забирать через клиент с
токеном и показывать как blob.

В ответе профиля есть `email` и `role` (оба только для чтения) и `avatar_url` — путь `/api/users/me/avatar?v=<версия>`.
Картинка лежит в MinIO, бакет `avatars` (`MINIO_AVATARS_BUCKET`), ключ объекта
`<user_id>/<версия>.<png|jpg|webp>`; ключ хранится в `auth.user_profiles.avatar_key`. При замене и сбросе старый объект
удаляется. Права auth-svc на бакет заданы в `infra/mtls/minio.conf` (GET, HEAD, PUT, DELETE только на `avatars`, в бакет
документов он не пускается). Тип определяется по сигнатуре файла, а не по `Content-Type`; если MinIO недоступен, ответ 503.
Группа (`group_name`) — свободная строка: пробелы схлопываются, пустая становится `null`, не длиннее 32
символов; справочника групп нет. `PATCH` проверяет, что `program_id` существует и относится к `faculty_id`.

## Справочники

Для выпадающих списков профиля, с авторизацией как у `/users/me`. Читаются из схемы `core` (роль `core_ro`).

| Метод | Endpoint | Назначение |
| ----- | -------- | ---------- |
| `GET` | `/core/faculties[?university_id=]` | Факультеты по алфавиту: `id, name, short_name` |
| `GET` | `/core/programs[?faculty_id=]` | Действующие направления: `id, name, short_name, code, degree_level` |

Снаружи — `/api/core/...` (отдельная локация в nginx и правило в `infra/mtls/auth-svc.conf`).

## Internal API

| Метод | Endpoint                            | Назначение                        |
| ----- | ----------------------------------- | --------------------------------- |
| `GET` | `/internal/users/{user_id}/profile` | Получение профиля другим сервисом |
| `POST` | `/internal/notifications/email-verification` | Повторное письмо подтверждения аккаунта (только `db-svc`) |

Internal API используется другими микросервисами, например `chat-svc`.

### Подтверждение почты аккаунта (IVHR-54 / IVHR-55)

Регистрация, публичная повторная отправка и внутренний маршрут используют единый сценарий
`app/verification.py`. Отдельный notification-сервис не нужен.

1. `POST /auth/register` создаёт аккаунт и профиль, сохраняет SHA-256 одноразового токена
   и отправляет письмо со ссылкой `${FRONTEND_BASE_URL}/verify-email?token=...`.
2. Страница frontend `/verify-email` вызывает `GET /auth/verify-email?token=...`.
3. Успешная проверка устанавливает `is_email_verified=true`; после этого разрешён вход.
   Все ранее выданные ссылки аккаунта становятся использованными. Параллельные запросы
   сериализуются блокировкой пользователя: подтвердить аккаунт можно только один раз.

Повторная регистрация существующей почты возвращает `400 Email already registered`
и **не меняет пароль**, даже если аккаунт ещё не подтверждён. Для нового письма используется
`POST /auth/resend-verification` с `{"email":"student@edu.hse.ru"}`. Через шлюз путь —
`/api/auth/resend-verification`; access-токен не требуется. Неизвестный, неактивный или уже
подтверждённый аккаунт получает одинаковый ответ `200`, письмо не отправляется.

Минимальный интервал отправки — `EMAIL_VERIFY_RESEND_COOLDOWN_SECONDS` (60 секунд).
Повтор в этот интервал, в том числе из другого сервиса, возвращает `429` с `Retry-After`.
Если SMTP не принял письмо, возвращается `503`, неудачный токен помечается использованным,
повторить отправку можно сразу. Созданный аккаунт сохраняется; регистрироваться заново
не нужно. Более старые неистёкшие ссылки сохраняют силу до первого успешного подтверждения.
Истёкшие, использованные ссылки, ссылки для прежнего адреса и неактивного аккаунта дают `400`.
Redis не принимает решений о валидности токена: источником истины остаётся PostgreSQL.

Внутренний вызов:

```http
POST /internal/notifications/email-verification
Content-Type: application/json

{"user_id":"11111111-1111-4111-8111-111111111111"}
```

Ответ `200 {"status":"sent"}` означает принятие письма SMTP-сервером, а не гарантированное
попадание во входящие. Для отсутствующего, неактивного или уже подтверждённого аккаунта —
`200 {"status":"skipped"}`. Адрес, HTML, тему и ссылку передавать нельзя (`422`): адрес
берётся из `auth.users`, секретный токен генерирует auth-svc. Вызывать может только `db-svc`;
в mTLS-политике основного репозитория ему разрешён ровно этот путь с методом POST.
Публичный шлюз и остальные сервисы к нему доступа не имеют. Заголовок `X-Caller-Identity`
формирует mTLS-прокси по сертификату; сам по себе клиентский заголовок не является авторизацией.

Шаблон `email_verification` читается из `core.email_templates` (миграция
`009_email_templates.sql` основного репозитория). В HTML должна быть ссылка
`<a href="{verification_url}">...</a>`. Значения экранируются, текстовая версия формируется
из HTML. При отсутствии БД, пустом шаблоне, неизвестных переменных, отсутствии правильной
ссылки или переносе строки в теме используется встроенный шаблон. Тот же механизм проверяет
шаблон сброса пароля с `{reset_url}`. Новые таблицы и миграции для этих изменений не нужны.

### Проверка подтверждения почты

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
# Дополнительно: настоящая PostgreSQL, уникальная временная схема, без изменения таблиц стенда.
TEST_DATABASE_URL=postgresql+asyncpg://test:test@localhost:5432/test python -m pytest -q
```

Без `TEST_DATABASE_URL` интеграционные тесты пропускаются. Пользователь тестовой БД должен
иметь право создавать схемы. Проверяются регистрация → письмо → подтверждение → вход,
ошибки SMTP и повторная отправка, запрет смены пароля повторной регистрацией, TTL и
параллельное использование ссылок, права внутреннего API. SMTP подменён в тестах:
для проверки реального почтового сервера нужны корректные `SMTP_*` и `EMAIL_FROM`.
Проверка nginx/mTLS без основного стека —
`python3 infra/mtls/tests/email_verification_policy.py` в основном репозитории.

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

## Подключение к PostgreSQL по сертификату

Если заданы `POSTGRES_SSLCERT`, `POSTGRES_SSLKEY` и `POSTGRES_SSLROOTCERT`, сервис входит в БД
по клиентскому сертификату (CN равен имени роли) вместо пароля и проверяет сервер: цепочку до
корня и имя хоста. Это делает `app/pg_tls.py`: он создаёт движок со своим `async_creator` и
собирает контекст TLS заново для каждого нового соединения, чтобы обновлённый сертификат
(он живёт сутки) подхватывался без перезапуска. Без этих переменных сервис работает как раньше,
по паролю из URL. Модуль одинаков во всех сервисах и лежит в каждом репозитории отдельной
копией, менять его нужно во всех сразу. Включение и проверка — `main/infra/db/README.md`.

## Контекст пользователя от шлюза

Профиль и админ-сессия (`get_current_user`) берут пользователя из подписанного контекста, а `/auth/validate?aud=...` и `/auth/validate-admin` его выписывают (мастер-ключ `USER_CONTEXT_MASTER_FILE`; допустимые аудитории `USER_CONTEXT_AUDIENCES`).

Раньше сервис верил голым заголовкам `X-User-Id` / `X-User-Role`, которые nginx дописывал после
проверки токена: любой контейнер в сети мог выставить их сам. Теперь auth-svc выписывает
подписанный токен `X-User-Context` (JWT HS256, минута жизни, привязан к аудитории `auth-svc`),
nginx пробрасывает его вместо заголовков, а сервис проверяет подпись ключом из
`USER_CONTEXT_KEY_FILE` (`app/user_context.py`, модуль одинаков во всех сервисах). У каждого
получателя ключ свой, производный от мастер-ключа auth-svc: скомпрометированный сервис не может
выпустить токен для другого. Без ключа сервис не стартует; прежнее поведение
(`USER_CONTEXT_ALLOW_LEGACY=true`) только на время перехода. Ключи: `main/scripts/gen_user_context_keys.py`,
проверка: `main/infra/nginx/tests/user_context_e2e.sh`. Упоминания `X-User-Id` в этом файле выше
описывают прежнюю схему.

## Метрики

`GET /metrics` отдаёт Prometheus (за mTLS - только пользователю `prometheus`, политика в `infra/mtls/auth-svc.conf`). Кроме HTTP-метрик (`http_requests_total`, `http_request_duration_seconds`, `http_requests_inprogress`; метка `handler` - шаблон маршрута) сервис отдаёт бизнес-метрики с префиксом `pochemuchnik_`. Код: `app/metrics.py`, тесты: `tests/`. Общая картина и дашборды - `infra/observability/README.md` в корневом репозитории.

| Метрика | Что считает |
| :-- | :-- |
| `registrations_total` | созданные учётные записи |
| `logins_total{result}` | попытки входа: `success`, `invalid_credentials`, `deactivated`, `email_not_verified` |
| `token_refresh_total{result}` | обновления токена: `success`, `missing`, `invalid`, `revoked`, `expired`, `user_inactive` |
| `emails_sent_total{kind,result}` | письма: `kind` - `verification`, `password_reset`; `result` - `sent`, `failed` |
| `admin_sessions_total` | открытые админ-сессии |

