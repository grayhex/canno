import logging
import secrets
from http.server import ThreadingHTTPServer

from canno import config
from canno.http.handlers import create_handler
from canno.repositories.db import QuestRepository, create_repository
from canno.services.quest_service import QuestService
from canno.services.stores import SqliteAuthStore

logging.basicConfig(
    level='INFO',
    format='%(asctime)s %(levelname)s %(message)s',
)
logger = logging.getLogger('canno')

service = QuestService()
DB_URL = config.CANNO_DATABASE_URL
repo = create_repository(DB_URL)
quest_repo = QuestRepository(repo)


def db():
    return repo.connect()


def now_dt():
    return service.now_dt()


def now():
    return service.now()


def next_day_start_iso():
    return service.next_day_start_iso()


def sanitize_text(raw, max_len=256):
    return service.sanitize_text(raw, max_len)


def parse_int(raw, default=None, minimum=None):
    return service.parse_int(raw, default, minimum)


def apply_migrations(conn=None):
    quest_repo.apply_migrations(now())


def init_db():
    apply_migrations()
    quest_repo.seed_demo(now(), secrets.token_urlsafe(8))


ADMIN_PASSWORD_HASH_VALUE = service.init_admin_password_hash()
AUTH_STORE = SqliteAuthStore(repo)
AUTH_STORE.ensure_schema()
H = create_handler(repo, service, ADMIN_PASSWORD_HASH_VALUE, AUTH_STORE)


if __name__ == '__main__':
    init_db()
    host = config.HTTP_HOST
    port = config.HTTP_PORT
    logger.info('Starting HTTP server on %s:%s', host, port)
    ThreadingHTTPServer((host, port), H).serve_forever()
