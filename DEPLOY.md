# Deploy Canno Quest (Production)

Обновлено: **2026-05-01**.

Этот документ описывает практичный деплой на ваш Linux-сервер через Docker Compose: с SQLite (самый простой вариант) или с Postgres (рекомендуется для более высокой нагрузки).

---

## 1. Что нужно на сервере

- Linux-сервер (Ubuntu/Debian/CentOS и т.п.).
- Установленные Docker Engine + Docker Compose Plugin.
- Открытый порт приложения (по умолчанию `8000/tcp`) **или** reverse proxy (Nginx/Caddy) перед приложением.
- SSH-доступ к серверу и доступ к репозиторию.

Проверка:

```bash
docker --version
docker compose version
```

---

## 2. Подготовка проекта

```bash
git clone <YOUR_REPOSITORY_URL> canno
cd canno
cp .env.example .env
```

Обязательно задайте в `.env`:

- `CANNO_ADMIN_USER`
- `CANNO_ADMIN_PASSWORD_HASH` (предпочтительно)
- `CANNO_SECRET_KEY` (длинный случайный ключ)

> Если нет готового hash-пароля, временно укажите `CANNO_ADMIN_PASSWORD`, запустите сервис и затем переведите конфиг на `CANNO_ADMIN_PASSWORD_HASH`.

Быстрая генерация секрета:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

---

## 3. Запуск (SQLite)

Самый простой и быстрый production-режим:

```bash
docker compose up -d --build
```

Проверки:

```bash
docker compose ps
docker compose logs -f web
```

Приложение будет доступно на:

- `http://<SERVER_IP>:8000`
- login: `http://<SERVER_IP>:8000/admin/login`

---

## 4. Запуск с Postgres (опционально)

Если хотите использовать Postgres-контейнер:

1) В `.env` задайте:

```dotenv
CANNO_DB_ENGINE=postgres
CANNO_DATABASE_URL=postgresql://canno:canno@postgres:5432/canno
```

2) Поднимите стек с профилем:

```bash
docker compose --profile postgres up -d --build
```

---

## 5. Reverse proxy и TLS (рекомендуется)

Минимально безопасная production-схема:

- Canno слушает только внутренний порт `8000`.
- Снаружи публикуется только Nginx/Caddy (`80/443`).
- TLS-сертификат: Let's Encrypt.

Это дает:

- HTTPS для админки,
- централизованный доступ/логи,
- проще ограничивать доступ по IP/VPN.

---

## 6. Обновление приложения

```bash
cd canno
git pull
docker compose up -d --build
```

Если менялась схема БД, миграции применяются при старте автоматически (`apply_migrations()`).

---

## 7. Бэкапы и восстановление

Создание бэкапа SQLite:

```bash
python3 backup_db.py --db canno.db --out-dir backups
```

Минимальная политика:

- каждые 6 часов;
- локальное хранение 7 дней;
- удаленная копия (S3/NAS) 30+ дней;
- еженедельный test-restore.

Восстановление:

```bash
docker compose down
cp backups/<backup-file>.db canno.db
docker compose up -d
```

Проверка целостности:

```bash
python3 - <<'PY'
import sqlite3
conn = sqlite3.connect('canno.db')
cur = conn.cursor()
cur.execute('PRAGMA integrity_check;')
print(cur.fetchone()[0])
conn.close()
PY
```

---

## 8. Smoke-check после деплоя

- Открывается `/admin/login`.
- Удается зайти под админом.
- Генерируется ссылка участника.
- Ссылка `/play/<token>` открывается.
- `docker compose ps` показывает `healthy` для `web`.

---

## 9. Hardening checklist

- [ ] `CANNO_SECRET_KEY` не дефолтный.
- [ ] Не использовать `change-me`/простые пароли.
- [ ] Секреты не хранятся в git.
- [ ] Есть firewall (например, UFW/security group).
- [ ] Настроен fail2ban/SSH hardening.
- [ ] Включена ротация Docker-логов.
- [ ] Настроен мониторинг (uptime + alerting).

