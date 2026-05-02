# 🎯 Canno Quest

Легкое веб-приложение для офлайн/ивент-квестов: участники получают уникальные ссылки, проходят этапы по паролям и таймерам, а админ управляет процессом из веб-панели.

---

## ✨ Возможности

- 🔐 **Админка с авторизацией** (`/admin/login`) и сессиями.
- 🧩 **Квесты с произвольным числом этапов**.
- 🔑 **Строгая проверка паролей этапов**.
- ⏱️ **Таймеры на этап и на весь квест**.
- 🚦 **Rate-limit** на вход в админку и на ввод паролей участником.
- 📊 **Метрики в админке** (`/admin/metrics`).
- 🧰 **CRUD квестов** + массовая генерация ссылок и CSV-экспорт.
- 🐳 **Docker-ready**: быстрый деплой через Compose.

---

## 🏗️ Архитектура

- `app.py` — bootstrap и запуск HTTP-сервера.
- `canno/http/handlers.py` — маршруты и HTTP-обработчики.
- `canno/services/quest_service.py` — бизнес-логика квеста.
- `canno/repositories/` — слой доступа к данным.
- `canno/templates/html.py` — HTML-шаблоны.

---

## 🚀 Быстрый старт (локально)

```bash
export CANNO_ADMIN_USER=admin
export CANNO_ADMIN_PASSWORD='change-me-please'
python3 app.py
```

Откройте: `http://localhost:8000`.

---

## 🐳 Запуск в Docker

```bash
cp .env.example .env
# Для Docker SQLite используйте персистентный путь в контейнере:
# CANNO_DATABASE_URL=sqlite:////data/canno.db
docker compose up -d --build
```

Проверка статуса:

```bash
docker compose ps
docker compose logs -f web
```

---

## 🛡️ Production-минимум

Перед выкладкой обязательно:

- задать надежные `CANNO_SECRET_KEY` и админ-пароль/hash;
- вынести TLS в reverse proxy (Nginx/Caddy);
- настроить бэкапы и мониторинг;
- проверить восстановление из бэкапа.

Подробная инструкция: **[`docs/DEPLOY.md`](./docs/DEPLOY.md)**.

---

## 🧪 Тесты

```bash
python3 -m unittest -v
```

Дополнительные рекомендации и сценарии проверки: `docs/TESTING.md`.

---

## 🗃️ Резервное копирование SQLite

Создать бэкап:

```bash
python3 scripts/backup_db.py --db canno.db --out-dir backups
# Для Docker используйте CANNO_DATABASE_URL=sqlite:////data/canno.db.
# Для локального запуска используйте sqlite://./canno.db (или просто путь canno.db),
# а не sqlite:///canno.db, чтобы не получить /canno.db в корне ФС.
```

Восстановить:

```bash
cp backups/canno_YYYYMMDDTHHMMSSZ.db canno.db
```

> Перед восстановлением остановите приложение.

---

## 📌 Статус

На **2026-05-01**: базовая функциональность, инфраструктура и тестовый контур для MVP готовы к deploy/use на сервере.

