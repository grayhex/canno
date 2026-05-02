# 🎯 Canno Quest

Веб-приложение для офлайн/ивент-квестов: участники проходят этапы по паролям и таймерам, а администратор и редактор управляют контентом через веб-панель.

---

## ✨ Текущие возможности

- 🔐 Раздельные роли и входы: `/admin/login` и `/editor/login`.
- 🧩 Создание и редактирование квестов с этапами, паролями и лимитами времени.
- 🚀 Запуск квеста по токену/ID (`/play/<token>`), отслеживание прогресса участника.
- 🕒 Таймер этапа с предупреждением о малом времени.
- 🛡️ Ограничение попыток входа и ввода паролей (rate-limit).
- 📦 Импорт квестов из JSON, экспорт квестов в JSON и участников/аудита в CSV.
- 🧾 Журнал аудита действий в админке.
- 🌐 Опциональная поддержка английского контента (через настройку).
- 🐳 Запуск в Docker Compose.

---

## 🏗️ Основные модули

- `app.py` — запуск HTTP-сервера и инициализация приложения.
- `canno/http/handlers.py` — роутинг, HTML-ответы, обработка форм, авторизация.
- `canno/services/quest_service.py` — бизнес-логика и валидация данных.
- `canno/services/stores.py` — сессии и хранилище попыток для rate-limit.
- `canno/repositories/db.py` — репозиторий и миграции БД (SQLite/PostgreSQL).
- `canno/templates/html.py` и `static.css` — UI-шаблон и стили.

---

## 🚀 Быстрый старт

```bash
export CANNO_ADMIN_USER=admin
export CANNO_ADMIN_PASSWORD='change-me-please'
export CANNO_EDITOR_USER=editor
export CANNO_EDITOR_PASSWORD='change-me-editor'
python3 app.py
```

Откройте `http://localhost:8000`.

---

## 🧪 Тесты

```bash
python3 -m unittest -v
```

Дополнительные сценарии: `docs/TESTING.md`.
