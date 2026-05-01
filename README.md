# Canno Quest

MVP для офлайн-квестов с уникальной ссылкой участника, этапами, паролями и таймерами.

## Запуск

```bash
export CANNO_ADMIN_USER=admin
export CANNO_ADMIN_PASSWORD='change-me'
python3 app.py
```

Откроется на `http://localhost:8000`.

## P0: безопасность и надежность

- `/admin` защищен логином/паролем, сессией и logout.
- Пароль админа хранится только как PBKDF2 hash (`CANNO_ADMIN_PASSWORD_HASH`), либо генерируется при старте из `CANNO_ADMIN_PASSWORD`.
- Rate-limit логина: `5` попыток за `5` минут с одного IP.
- Rate-limit для ввода пароля этапа: `8` попыток за `5` минут на пару `IP+token`.
- Санитизация и ограничения длины для `username`, `password`, `token`, `quest_id`, `title`, `prompt`.
- Централизованный logging через `logging` (INFO/WARN/ERROR).
- Безопасные страницы ошибок `404`/`500` без утечки деталей.

## Миграции БД

При старте вызывается `apply_migrations()`:

- создается `schema_migrations`;
- если версия `0`, применяется migration `v1` и создаются таблицы `quests`, `steps`, `participants`, `attempts`.

Это делает изменение схемы воспроизводимым на любых окружениях.

## Резервное копирование и восстановление SQLite

Создать бэкап:

```bash
python3 backup_db.py --db canno.db --out-dir backups
```

Восстановить из бэкапа:

```bash
cp backups/canno_YYYYMMDDTHHMMSSZ.db canno.db
```

(Перед восстановлением остановите приложение.)

## Что реализовано
- Участник проходит квест по уникальному `/play/<token>`.
- Количество этапов произвольное.
- Строгая проверка пароля.
- Таймер на квест и на этап.
- При истечении времени блокировка до следующего дня по `Europe/Moscow`.
- Админка `/admin`: авторизация, генерация ссылок и просмотр прогресса.
