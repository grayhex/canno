import os
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

DB = 'canno.db'
CANNO_DATABASE_URL = os.getenv('CANNO_DATABASE_URL', f'sqlite:///{DB}')
TZ = ZoneInfo('Europe/Moscow')
SESSION_COOKIE = 'canno_admin_session'
ADMIN_USER = os.getenv('CANNO_ADMIN_USER', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('CANNO_ADMIN_PASSWORD_HASH')
ADMIN_PASSWORD = os.getenv('CANNO_ADMIN_PASSWORD')
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
MAX_STEP_ATTEMPTS = 8
STEP_ATTEMPT_WINDOW_SECONDS = 300


def database_scheme() -> str:
    return urlparse(CANNO_DATABASE_URL).scheme
