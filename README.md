# 🎯 Canno Quest

Легкое веб-приложение для офлайн/ивент-квестов: участники получают уникальные ссылки, проходят этапы по паролям и таймерам, а админ и редактор управляют контентом из веб-панели.

---

## ✨ Возможности

- 🔐 **Раздельные входы по ролям**: `/admin/login` и `/editor/login`.
- 🧩 **Квесты с произвольным числом этапов**.
- 🔑 **Строгая проверка паролей этапов**.
- ⏱️ **Таймеры на этап и на весь квест**.
- 🚦 **Rate-limit** на вход и на ввод паролей участником.
- 📊 **Метрики и аудит** для администратора.
- 🧰 **CRUD квестов** + массовая генерация ссылок и CSV/JSON-экспорт.
- 🐳 **Docker-ready**: быстрый деплой через Compose.

---

## 🏗️ Архитектура

- `app.py` — bootstrap и запуск HTTP-сервера.
- `canno/http/handlers.py` — маршруты, авторизация, роли, HTTP-обработчики.
- `canno/services/quest_service.py` — бизнес-логика квеста.
- `canno/repositories/` — слой доступа к данным.
- `canno/services/stores.py` — сессии и ограничение попыток (auth store).
- `canno/templates/html.py` — HTML-шаблоны.

---

## 👥 Роли и доступы

В приложении есть:

- **Admin** — полный доступ к `/admin`, метрикам, аудиту, настройкам и экспорту.
- **Editor** — управление квестами и этапами без доступа к админ-отчетам.
- **Участник** — проходит квест по персональной ссылке `/play/<token>`.

Полная матрица прав и логика авторизации: **[`docs/ROLES.md`](./docs/ROLES.md)**.

---

## 🔐 Где задаются логины и пароли

Через переменные окружения:

- `CANNO_ADMIN_USER`, `CANNO_ADMIN_PASSWORD`, `CANNO_ADMIN_PASSWORD_HASH`
- `CANNO_EDITOR_USER`, `CANNO_EDITOR_PASSWORD`, `CANNO_EDITOR_PASSWORD_HASH`

Рекомендация для production: использовать `*_PASSWORD_HASH`, а не открытые `*_PASSWORD`.

---

## 🚀 Быстрый старт (локально)

```bash
export CANNO_ADMIN_USER=admin
export CANNO_ADMIN_PASSWORD='change-me-please'
export CANNO_EDITOR_USER=editor
export CANNO_EDITOR_PASSWORD='change-me-editor'
python3 app.py
```

Откройте: `http://localhost:8000`.

- Вход администратора: `http://localhost:8000/admin/login`
- Вход редактора: `http://localhost:8000/editor/login`

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

- задать надежные `CANNO_SECRET_KEY` (если используется в вашем окружении), логины и пароли/хеши ролей;
- хранить секреты в secret manager или переменных окружения, а не в репозитории;
- вынести TLS в reverse proxy (Nginx/Caddy);
- настроить бэкапы и мониторинг;
- проверить восстановление из бэкапа.

Подробная инструкция: **[`docs/DEPLOY.md`](./docs/DEPLOY.md)**.

---

## 🧪 Тесты

```bash
python3 -m unittest -v
```

Дополнительные сценарии проверки: `docs/TESTING.md`.

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

На **2026-05-02**: MVP стабилен, ролевая модель `admin/editor` реализована и документирована для пользовательской эксплуатации.
