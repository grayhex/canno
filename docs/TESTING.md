# Тестирование

## Что покрыто

- Unit: `parse_int`, `sanitize_text`, `next_day_start_iso`.
- Integration: HTTP-поток через локальный `HTTPServer` для `/play/<token>` и `/admin/login`.
- Smoke: подъем приложения в тестовой БД и обработка реального HTTP-запроса.

## Как запустить

```bash
python3 -m unittest discover -s tests -v
```

## Цель

Минимальный тестовый набор из P1.8: падение тестов должно блокировать merge в CI после подключения CI-пайплайна (P2.11).

## Disaster Recovery (test-restore)

Ниже — регламентная процедура проверки, что резервная копия реально восстанавливается.

### Когда проводить

- Минимум 1 раз в неделю.
- Дополнительно: перед релизом и после изменений в схеме БД.

### Пошаговый сценарий

1. Создать свежий backup:

```bash
python3 scripts/backup_db.py --db canno.db --out-dir backups
```

2. Найти последний файл backup:

```bash
LATEST_BACKUP=$(ls -1t backups/canno_*.db | head -n 1)
echo "$LATEST_BACKUP"
```

3. Восстановить копию в отдельный тестовый файл:

```bash
cp "$LATEST_BACKUP" restore_test.db
```

4. Проверить, что SQLite открывает файл и что ключевые таблицы на месте:

```bash
python3 - <<'PY'
import sqlite3

path = "restore_test.db"
required = {"schema_migrations", "quests", "steps", "participants", "attempts"}

conn = sqlite3.connect(path)
cur = conn.cursor()
cur.execute("PRAGMA integrity_check;")
status = cur.fetchone()[0]
if status != "ok":
    raise SystemExit(f"Integrity check failed: {status}")

cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = {row[0] for row in cur.fetchall()}
missing = sorted(required - tables)
if missing:
    raise SystemExit(f"Missing required tables: {', '.join(missing)}")

cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
version = cur.fetchone()[0]
print(f"Restore test passed. Schema version={version}")
conn.close()
PY
```

5. Удалить временный restore-файл:

```bash
rm -f restore_test.db
```

### Критерий успеха

- `PRAGMA integrity_check` возвращает `ok`.
- Все обязательные таблицы присутствуют.
- Читается текущая версия схемы из `schema_migrations`.
