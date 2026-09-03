# Auth Service — API и функциональность

## 1. Назначение сервиса

`auth-svc` — микросервис аутентификации и управления учётными записями пользователей. Он отвечает за регистрацию пользователей, подтверждение электронной почты, авторизацию, выдачу и обновление JWT access token, управление refresh token, выход из системы, восстановление пароля, работу с профилем пользователя и предоставление внутреннего API для других микросервисов.

Сервис реализован на FastAPI и работает с PostgreSQL через SQLAlchemy. JWT используется для пользовательской аутентификации, а для межсервисных запросов предусмотрена отдельная схема с сервисным именем и сервисным токеном. Структура приложения разделяет authentication API, profile API и internal API.

В рамках системы `auth-svc` является источником истины для данных об аккаунте пользователя и его профиле. Другие микросервисы могут обращаться к нему для получения информации о пользователе через защищённый internal API.

---

## 2. Основные функции

Сервис предоставляет следующие возможности:

* регистрация пользователя;
* хранение пароля в хешированном виде;
* подтверждение email;
* повторная отправка verification token;
* авторизация по email и паролю;
* выдача JWT access token;
* выдача refresh token;
* обновление access token через refresh token;
* logout и отзыв refresh token;
* проверка действительности access token;
* восстановление пароля;
* установка нового пароля по reset token;
* получение профиля пользователя;
* изменение профиля пользователя;
* деактивация пользовательского аккаунта;
* получение профиля пользователя другими микросервисами;
* health check сервиса.

---

# 3. Архитектура авторизации

Для обычного пользователя применяется JWT-based authentication.

После успешной авторизации сервер возвращает access token:

```json
{
  "access_token": "<JWT>",
  "token_type": "bearer"
}
```

Access token передаётся клиентом в каждом защищённом запросе:

```http
Authorization: Bearer <access_token>
```

JWT содержит идентификатор пользователя в `sub` и его роль в `role`. Срок жизни access token задаётся переменной `ACCESS_TOKEN_EXPIRE_MINUTES`.

Refresh token используется отдельно от access token. Он хранится в `HttpOnly` cookie `refresh_token`, поэтому frontend не должен передавать его вручную в JSON body.

Схематично процесс выглядит следующим образом:

```text
                   +------------------+
                   |     Frontend     |
                   +---------+--------+
                             |
                             | POST /auth/login
                             v
                   +---------+--------+
                   |    auth-svc      |
                   +---------+--------+
                      |           |
                      |           |
                      v           v
                 PostgreSQL    JWT/refresh
```

Для межсервисного взаимодействия используется другой механизм:

```text
chat-svc / library-svc / ...
            |
            | X-Service-Name
            | X-Service-Token
            v
        auth-svc
            |
            v
       user profile
```

Проверка internal API основана на `TRUSTED_SERVICE_TOKENS`.

---

# 4. Base URL

При стандартном запуске API доступен по адресу:

```text
http://<auth-svc-host>:8000
```

В Docker hostname должен соответствовать имени контейнера или сервиса в Docker Compose.

FastAPI также автоматически предоставляет OpenAPI/Swagger интерфейс, если он не отключён конфигурацией приложения.

---

# 5. Authentication API

Все authentication endpoints находятся под префиксом:

```text
/auth
```

## 5.1 Регистрация

### `POST /auth/register`

Создаёт нового пользователя.

Request:

```json
{
  "email": "student@example.com",
  "password": "strong-password"
}
```

Поля:

| Поле       | Тип    | Обязательное |
| ---------- | ------ | ------------ |
| `email`    | string | да           |
| `password` | string | да           |

При создании пользователя сервис создаёт учётную запись и связанный профиль пользователя. Для нового пользователя также создаётся verification token.

Успешный результат:

```http
201 Created
```

Пример ответа:

```json
{
  "id": "6e9d...",
  "email": "student@example.com",
  "role": "student",
  "is_email_verified": false,
  "is_active": true
}
```

Если пользователь уже существует и его email подтверждён, сервис возвращает ошибку `400`.

Если пользователь существует, но email ещё не подтверждён, текущая реализация позволяет повторно инициировать процесс регистрации/подтверждения.

---

## 5.2 Повторная отправка подтверждения email

### `POST /auth/resend-verification`

Создаёт новый verification token для существующего неподтверждённого пользователя.

Request:

```json
{
  "email": "student@example.com"
}
```

Ответ:

```json
{
  "detail": "If the account exists and is unverified, a new link has been sent."
}
```

API намеренно не раскрывает, существует ли указанный email, чтобы не позволять проверять наличие аккаунтов по email.

---

## 5.3 Подтверждение email

### `GET /auth/verify-email?token=<token>`

Подтверждает email пользователя.

Пример:

```http
GET /auth/verify-email?token=<verification-token>
```

При успешной обработке:

```text
is_email_verified = true
```

Verification token становится использованным.

Ответ:

```json
{
  "msg": "Email successfully verified"
}
```

При некорректном или уже использованном token:

```http
400 Bad Request
```

---

## 5.4 Авторизация

### `POST /auth/login`

Авторизация пользователя по email и паролю.

Request:

```json
{
  "email": "student@example.com",
  "password": "strong-password"
}
```

Для успешной авторизации пользователь должен:

* существовать;
* иметь корректный пароль;
* быть активным;
* иметь подтверждённый email.

При успешной авторизации сервис возвращает access token и создаёт refresh token.

Ответ:

```json
{
  "access_token": "<JWT>",
  "token_type": "bearer"
}
```

Refresh token одновременно устанавливается в cookie:

```text
refresh_token=<token>
```

Cookie имеет атрибут `HttpOnly`, что препятствует чтению значения через JavaScript.

---

## 5.5 Обновление access token

### `POST /auth/refresh`

Используется для получения нового access token без повторного ввода логина и пароля.

Refresh token передаётся автоматически через cookie:

```http
Cookie: refresh_token=<refresh-token>
```

Request body не требуется.

Ответ:

```json
{
  "access_token": "<new-access-token>",
  "token_type": "bearer"
}
```

При успешном refresh старый refresh token отзывается, создаётся новый refresh token и обновляется cookie.

В текущей реализации lifetime refresh token установлен непосредственно в коде и составляет 30 дней.

---

## 5.6 Logout

### `POST /auth/logout`

Выполняет выход из системы.

Сервис отзывает refresh token и удаляет соответствующую cookie.

Пример:

```http
POST /auth/logout
Cookie: refresh_token=<refresh-token>
```

Ответ:

```json
{
  "detail": "Successfully logged out"
}
```

---

## 5.7 Проверка access token

### `GET /auth/validate`

Проверяет JWT access token.

Request:

```http
Authorization: Bearer <access-token>
```

При успешной проверке:

```json
{
  "status": "valid"
}
```

Кроме тела ответа, сервис возвращает headers:

```http
X-User-Id: <user-uuid>
X-User-Role: <user-role>
```

Этот endpoint предназначен в первую очередь для gateway/Nginx.

Схема работы может выглядеть так:

```text
Client
   |
   | Authorization: Bearer JWT
   v
Gateway / Nginx
   |
   | GET /auth/validate
   v
auth-svc
   |
   | X-User-Id
   | X-User-Role
   v
downstream service
```

Таким образом, downstream-сервису не обязательно самостоятельно реализовывать проверку JWT.

---

## 5.8 Восстановление пароля

### `POST /auth/forgot-password`

Инициирует процедуру восстановления пароля.

Request:

```json
{
  "email": "student@example.com"
}
```

Если пользователь существует, сервис создаёт одноразовый reset token.

API возвращает одинаковый ответ независимо от существования аккаунта:

```json
{
  "detail": "If the email is registered, a password reset link has been sent."
}
```

Это предотвращает раскрытие списка зарегистрированных пользователей.

### Важная особенность текущей реализации

В текущей версии SMTP-отправка письма фактически не реализована. Вместо отправки email ссылка для восстановления выводится в stdout контейнера. Следовательно, `forgot-password` функционально генерирует reset token, но полноценная отправка письма через SMTP пока отсутствует.

---

## 5.9 Установка нового пароля

### `POST /auth/update-password`

Используется с reset token.

Request:

```json
{
  "token": "<reset-token>",
  "new_password": "new-strong-password"
}
```

Token должен существовать и не быть использованным.

Текущий код считает reset token недействительным после одного часа.

При успехе:

```json
{
  "detail": "Password has been updated successfully"
}
```

После использования token становится недействительным.

---

# 6. User Profile API

API профиля находится под префиксом:

```text
/users
```

В текущей архитектуре профиль идентифицируется через `X-User-Id`.

Этот header должен быть установлен после успешной проверки JWT gateway-уровнем.

---

## 6.1 Получение собственного профиля

### `GET /users/me`

Возвращает профиль текущего пользователя.

Пример ответа:

```json
{
  "user_id": "6e9d...",
  "first_name": "Ivan",
  "last_name": "Ivanov",
  "telegram_username": "ivanov",
  "university_id": "uuid",
  "campus_id": "uuid",
  "faculty_id": "uuid",
  "program_id": "uuid",
  "year": 3,
  "group_name": "ИУ7-21"
}
```

Профиль содержит основные персональные и учебные данные пользователя.

---

## 6.2 Изменение профиля

### `PATCH /users/me`

Позволяет частично изменить профиль.

Пример:

```json
{
  "first_name": "Ivan",
  "last_name": "Ivanov",
  "telegram_username": "ivanov",
  "university_id": "uuid",
  "faculty_id": "uuid",
  "program_id": "uuid",
  "year": 3,
  "group_name": "ИУ7-21"
}
```

Все поля являются опциональными.

Обновляются только поля, которые были переданы в запросе.

---

## 6.3 Деактивация аккаунта

### `DELETE /users/me`

Удаляет учётную запись пользователя с точки зрения приложения.

При этом физического удаления строки пользователя из PostgreSQL не происходит.

Вместо этого:

```text
is_active = false
```

То есть используется soft delete.

Это позволяет сохранить связанные данные пользователя и не нарушать связи с другими сущностями системы, например историей сообщений.

Успешный ответ:

```http
204 No Content
```

---

# 7. Internal API для микросервисов

Internal API находится под префиксом:

```text
/internal
```

Эти endpoints не предназначены для frontend.

Они используются другими сервисами системы.

---

## 7.1 Получение профиля пользователя

### `GET /internal/users/{user_id}/profile`

Возвращает данные пользователя по его UUID.

Пример:

```http
GET /internal/users/6e9d.../profile
```

Для обращения должны присутствовать headers:

```http
X-Service-Name: chat-svc
X-Service-Token: <service-token>
```

`auth-svc` проверяет соответствие `X-Service-Name` и token записи в `TRUSTED_SERVICE_TOKENS`.

При отсутствии необходимых headers:

```http
401 Unauthorized
```

При неверном service token:

```http
403 Forbidden
```

Успешный ответ:

```json
{
  "id": "6e9d...",
  "email": "student@example.com",
  "role": "student",
  "profile": {
    "first_name": "Ivan",
    "last_name": "Ivanov",
    "telegram_username": "ivanov",
    "university_id": "uuid",
    "campus_id": "uuid",
    "faculty_id": "uuid",
    "program_id": "uuid",
    "year": 3,
    "group_name": "ИУ7-21",
    "preferences": {}
  }
}
```

Этот endpoint позволяет, например, `chat-svc` получить информацию о пользователе, не храня собственную копию пользовательских данных.

---

# 8. Health Check

### `GET /health`

Используется для проверки доступности сервиса.

Ответ:

```json
{
  "status": "ok",
  "service": "auth"
}
```

Endpoint подходит для Docker healthcheck, orchestration и мониторинга.

---

# 9. Модель пользователя

На уровне функциональности пользователь имеет как минимум следующие атрибуты:

```text
id
email
password
role
is_email_verified
is_active
```

Отдельно связан профиль пользователя.

Профиль хранит данные, связанные с пользовательским контекстом:

```text
first_name
last_name
telegram_username
university_id
campus_id
faculty_id
program_id
year
group_name
preferences
```

Таким образом, сервис разделяет authentication data и profile data, сохраняя их связанными.

---

# 10. Работа с ролями

JWT содержит поле:

```text
role
```

Поэтому роль пользователя доступна другим компонентам системы после проверки токена.

Например:

```json
{
  "sub": "6e9d...",
  "role": "student"
}
```

Текущая реализация поддерживает использование роли как части authentication context.

---

# 11. Работа с PostgreSQL

`auth-svc` напрямую подключается к PostgreSQL.

Connection string задаётся переменной:

```env
DATABASE_URL=postgresql+asyncpg://...
```

`DATABASE_URL` используется непосредственно модулем подключения к БД.

Важно, что `DATABASE_URL` относится к соединению **самого auth-сервиса с PostgreSQL**, а не к взаимодействию между микросервисами.

При Docker-запуске hostname БД должен указывать на имя PostgreSQL-сервиса в Docker network, например:

```env
DATABASE_URL=postgresql+asyncpg://app_user:app_password@postgres:5432/auth_db
```

---

# 12. Переменные окружения

Для текущей реализации основными рабочими переменными являются:

```env
DATABASE_URL

SECRET_KEY
ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES

INTERNAL_AUTH_HEADER_NAME
INTERNAL_SERVICE_NAME_HEADER
TRUSTED_SERVICE_TOKENS
```

Назначение:

| Переменная                     | Назначение                                   |
| ------------------------------ | -------------------------------------------- |
| `DATABASE_URL`                 | Подключение auth-svc к PostgreSQL            |
| `SECRET_KEY`                   | Секрет для подписи JWT                       |
| `ALGORITHM`                    | Алгоритм подписи JWT                         |
| `ACCESS_TOKEN_EXPIRE_MINUTES`  | Срок действия access token                   |
| `INTERNAL_AUTH_HEADER_NAME`    | Название header с internal service token     |
| `INTERNAL_SERVICE_NAME_HEADER` | Название header с именем вызывающего сервиса |
| `TRUSTED_SERVICE_TOKENS`       | Разрешённые service-to-service credentials   |

В текущей версии `REDIS_URL`, SMTP-переменные и несколько переменных, связанных со сроками действия отдельных токенов, не являются рабочими настройками существующей реализации.

---

# 13. Важные ограничения текущей реализации

Документация должна учитывать не только предусмотренную функциональность, но и фактическое поведение текущего кода.

### Email

Verification и password reset поддерживаются на уровне API, однако полноценная отправка email через SMTP ещё не реализована. Сейчас ссылки выводятся в stdout приложения.

### Refresh token lifetime

Срок действия refresh token не вынесен в environment configuration. Сейчас используется фиксированное значение 30 дней.

### Verification token lifetime

Несмотря на наличие соответствующей переменной в старом `.env.example`, текущая реализация не использует `EMAIL_VERIFY_TOKEN_EXPIRE_MINUTES` для проверки срока действия verification token.

### Password reset lifetime

Срок жизни reset token определяется непосредственно кодом и составляет один час.

### Redis

`auth-svc` не использует Redis в текущей реализации.

### Soft delete

`DELETE /users/me` не удаляет пользователя физически, а только деактивирует его.

### Internal API

Internal API защищён отдельным сервисным механизмом и не должен быть доступен публичным клиентам.

---

# 14. Итоговая роль auth-svc в системе

В микросервисной архитектуре `auth-svc` выполняет роль центрального сервиса идентификации пользователя.

Его ответственность:

```text
                    +------------------+
                    |     Frontend     |
                    +--------+---------+
                             |
                             | login / refresh / profile
                             v
                    +--------+---------+
                    |    auth-svc      |
                    +--------+---------+
                       |      |      |
                       |      |      |
                       v      v      v
                  PostgreSQL  JWT  Internal API
                                      |
                         +------------+-------------+
                         |            |             |
                         v            v             v
                     chat-svc    library-svc     другие
```

То есть `auth-svc` отвечает за:

**Кто пользователь?**

```text
email
password
JWT
refresh token
role
is_active
is_email_verified
```

**Какие данные профиля у него есть?**

```text
first_name
last_name
Telegram
university
faculty
program
group
year
preferences
```

**Можно ли доверять запросу от другого микросервиса?**

```text
X-Service-Name
X-Service-Token
TRUSTED_SERVICE_TOKENS
```

**Может ли другой сервис получить информацию о пользователе?**

Да, через:

```http
GET /internal/users/{user_id}/profile
```

Таким образом, `auth-svc` является не просто endpoint'ом для login, а центральным сервисом управления identity пользователя и его профилем, через который остальные микросервисы получают необходимый authentication context.
