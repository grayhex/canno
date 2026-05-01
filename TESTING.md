# Тестирование

## Что покрыто

- Unit: `parse_int`, `sanitize_text`, `next_day_start_iso`.
- Integration: HTTP-поток через локальный `HTTPServer` для `/play/<token>` и `/admin/login`.
- Smoke: подъем приложения в тестовой БД и обработка реального HTTP-запроса.

## Как запустить

```bash
python3 -m unittest -v
```

## Цель

Минимальный тестовый набор из P1.8: падение тестов должно блокировать merge в CI после подключения CI-пайплайна (P2.11).
