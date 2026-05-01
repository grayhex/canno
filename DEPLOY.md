# Деплой Canno Quest

Документ описывает базовый production-деплой через Docker Compose.

## 1) Предварительные требования

- Linux-сервер с установленными Docker и Docker Compose Plugin.
- Открыт порт приложения (по умолчанию `8000/tcp`) либо настроен reverse proxy.
- Доступ к репозиторию проекта.

## 2) Подготовка окружения

1. Склонируйте репозиторий и перейдите в директорию проекта.
2. Создайте файл окружения из шаблона:

```bash
cp .env.example .env
```

3. Обязательно задайте безопасные значения:
   - `CANNO_ADMIN_USER`
   - `CANNO_ADMIN_PASSWORD_HASH` (предпочтительно) или `CANNO_ADMIN_PASSWORD`
   - `CANNO_SECRET_KEY`
4. Проверьте БД-настройки:
   - для SQLite: `CANNO_DB_ENGINE=sqlite`
   - для Postgres-окружения: включите профиль compose `postgres` и задайте `CANNO_DATABASE_URL`

## 3) Запуск приложения

### Вариант A: SQLite (по умолчанию)

```bash
docker compose up -d --build
```

### Вариант B: с Postgres-контейнером

```bash
docker compose --profile postgres up -d --build
```

После старта проверьте доступность приложения: `http://<server-ip>:8000`.

## 4) Проверка после деплоя

- Откройте `/admin/login` и выполните вход админом.
- Создайте тестового участника и убедитесь, что ссылка `/play/<token>` открывается.
- Проверьте логи:

```bash
docker compose logs -f app
```

## 5) Обновление на новую версию

```bash
git pull
docker compose up -d --build
```

Если менялась схема БД, миграции применятся при старте приложения автоматически (`apply_migrations()`).

## 6) Резервное копирование

Для SQLite-базы:

```bash
python3 backup_db.py --db canno.db --out-dir backups
```

Регламент резервного копирования (минимум):

- Частота: каждые 6 часов.
- Хранение: локально минимум 7 суток + удаленная копия (S3/NAS/объектное хранилище) минимум 30 суток.
- Ротация: ежедневно удалять локальные копии старше 7 дней, удаленные — старше 30 дней.
- Проверка целостности: ежедневно запускать проверку открытия backup-файла и `PRAGMA integrity_check`; минимум 1 раз в неделю выполнять test-restore (см. `TESTING.md`).

## 7) Откат

1. Остановите приложение: `docker compose down`.
2. Восстановите БД из бэкапа.
3. Поднимите сервис снова: `docker compose up -d`.

## 8) Аварийное восстановление (Disaster Recovery)

### Целевые показатели

- **RPO (Recovery Point Objective):** до 6 часов потери данных.
- **RTO (Recovery Time Objective):** до 60 минут на восстановление сервиса.

### Шаги восстановления

1. Зафиксируйте инцидент и остановите запись в систему:

```bash
docker compose down
```

2. Выберите последний корректный backup (предпочтительно проверенный nightly/weekly валидацией).
3. Восстановите рабочую БД:

```bash
cp backups/<backup-file>.db canno.db
```

4. Проверьте целостность:

```bash
python3 - <<'PY'
import sqlite3
conn = sqlite3.connect("canno.db")
cur = conn.cursor()
cur.execute("PRAGMA integrity_check;")
print(cur.fetchone()[0])
conn.close()
PY
```

5. Поднимите приложение:

```bash
docker compose up -d
```

6. Проведите smoke-проверку:
   - вход в `/admin/login`;
   - открытие `/play/<token>`;
   - проверка логов `docker compose logs -f app`.

## 9) Минимальные production-рекомендации

- Использовать reverse proxy (Nginx/Caddy) + TLS.
- Ограничить доступ к Docker socket и SSH.
- Включить ротацию логов Docker.
- Вынести секреты в защищенное хранилище.
