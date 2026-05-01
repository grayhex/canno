import logging
import secrets
from http.server import HTTPServer

from canno import config
from canno.http.handlers import create_handler
from canno.repositories.sqlite_repo import SqliteRepository
from canno.services.quest_service import QuestService
from canno.services.stores import SqliteAuthStore

logging.basicConfig(
    level='INFO',
    format='%(asctime)s %(levelname)s %(message)s',
)
logger = logging.getLogger('canno')

service = QuestService()
DB = config.DB


def _db_path():
    return DB


repo = SqliteRepository(_db_path)


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


def apply_migrations(conn):
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)')
    version = cur.execute('SELECT COALESCE(MAX(version), 0) v FROM schema_migrations').fetchone()['v']
    if version < 1:
        cur.executescript('''
CREATE TABLE quests (id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,final_location TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,quest_time_limit_sec INTEGER);
CREATE TABLE steps (id INTEGER PRIMARY KEY AUTOINCREMENT,quest_id INTEGER NOT NULL,idx INTEGER NOT NULL,prompt TEXT NOT NULL,password TEXT NOT NULL,step_time_limit_sec INTEGER,FOREIGN KEY(quest_id) REFERENCES quests(id));
CREATE TABLE participants (id INTEGER PRIMARY KEY AUTOINCREMENT,quest_id INTEGER NOT NULL,token TEXT NOT NULL UNIQUE,current_step INTEGER NOT NULL DEFAULT 1,started_at TEXT,step_started_at TEXT,locked_until TEXT,completed INTEGER NOT NULL DEFAULT 0,FOREIGN KEY(quest_id) REFERENCES quests(id));
CREATE TABLE attempts (id INTEGER PRIMARY KEY AUTOINCREMENT,participant_id INTEGER NOT NULL,step_idx INTEGER NOT NULL,entered_password TEXT NOT NULL,success INTEGER NOT NULL,created_at TEXT NOT NULL,FOREIGN KEY(participant_id) REFERENCES participants(id));
''')
        cur.execute('INSERT INTO schema_migrations(version, applied_at) VALUES (?,?)', (1, now()))
    if version < 2:
        cur.execute("ALTER TABLE participants ADD COLUMN status TEXT NOT NULL DEFAULT 'new'")
        cur.execute('INSERT INTO schema_migrations(version, applied_at) VALUES (?,?)', (2, now()))
    conn.commit()


def init_db():
    c = db(); cur = c.cursor(); apply_migrations(c)
    q = cur.execute('SELECT COUNT(*) c FROM quests').fetchone()['c']
    if q == 0:
        cur.execute('INSERT INTO quests(title, final_location, active, quest_time_limit_sec) VALUES (?,?,?,?)', ('Демо-квест', 'Под стойкой у окна', 1, 3600))
        quest_id = cur.lastrowid
        steps = [
            (quest_id, 1, 'Найди бумажку возле входной двери и введи слово.', 'СОЛНЦЕ', 600),
            (quest_id, 2, 'Ищи под столом в переговорной.', 'ЛИСТ', 600),
        ]
        cur.executemany('INSERT INTO steps(quest_id,idx,prompt,password,step_time_limit_sec) VALUES (?,?,?,?,?)', steps)
        token = secrets.token_urlsafe(8)
        cur.execute('INSERT INTO participants(quest_id, token, started_at, step_started_at) VALUES (?,?,?,?)', (quest_id, token, now(), now()))
        c.commit()
    c.close()


ADMIN_PASSWORD_HASH_VALUE = service.init_admin_password_hash()
AUTH_STORE = SqliteAuthStore(repo)
AUTH_STORE.ensure_schema()
H = create_handler(repo, service, ADMIN_PASSWORD_HASH_VALUE, AUTH_STORE)


if __name__ == '__main__':
    init_db()
    logger.info('Starting HTTP server on 0.0.0.0:8000')
    HTTPServer(('0.0.0.0', 8000), H).serve_forever()
