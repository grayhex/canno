import os
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

DB = 'canno.db'


def _resolve_database_url() -> str:
    raw_url = os.getenv('CANNO_DATABASE_URL')
    if raw_url and raw_url.strip():
        return raw_url

    db_engine = os.getenv('CANNO_DB_ENGINE', 'sqlite')
    db_path = os.getenv('CANNO_DB_PATH', DB)
    if db_engine == 'sqlite':
        return f'sqlite:///{db_path}'

    return f'sqlite:///{DB}'


CANNO_DATABASE_URL = _resolve_database_url()
TZ = ZoneInfo('Europe/Moscow')
SESSION_COOKIE = 'canno_session'
ADMIN_USER = os.getenv('CANNO_ADMIN_USER', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('CANNO_ADMIN_PASSWORD_HASH')
ADMIN_PASSWORD = os.getenv('CANNO_ADMIN_PASSWORD')
EDITOR_USER = os.getenv('CANNO_EDITOR_USER', 'editor')
EDITOR_PASSWORD_HASH = os.getenv('CANNO_EDITOR_PASSWORD_HASH')
EDITOR_PASSWORD = os.getenv('CANNO_EDITOR_PASSWORD')
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
MAX_STEP_ATTEMPTS = 8
STEP_ATTEMPT_WINDOW_SECONDS = 300


def database_scheme() -> str:
    return urlparse(CANNO_DATABASE_URL).scheme
