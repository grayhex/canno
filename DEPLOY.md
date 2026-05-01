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

Рекомендуется выполнять по расписанию (cron/systemd timer) и хранить копии на внешнем хранилище.

## 7) Откат

1. Остановите приложение: `docker compose down`.
2. Восстановите БД из бэкапа.
3. Поднимите сервис снова: `docker compose up -d`.

## 8) Минимальные production-рекомендации

- Использовать reverse proxy (Nginx/Caddy) + TLS.
- Ограничить доступ к Docker socket и SSH.
- Включить ротацию логов Docker.
- Вынести секреты в защищенное хранилище.
