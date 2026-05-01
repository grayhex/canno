import hashlib
import hmac
import html as html_lib
import json
import logging
import os
import secrets
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

DB = 'canno.db'
TZ = ZoneInfo('Europe/Moscow')
SESSION_COOKIE = 'canno_admin_session'
ADMIN_USER = os.getenv('CANNO_ADMIN_USER', 'admin')
ADMIN_PASSWORD_HASH = os.getenv('CANNO_ADMIN_PASSWORD_HASH')
ADMIN_PASSWORD = os.getenv('CANNO_ADMIN_PASSWORD')
LOGIN_ATTEMPTS = {}
STEP_ATTEMPTS = {}
SESSIONS = {}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300
MAX_STEP_ATTEMPTS = 8
STEP_ATTEMPT_WINDOW_SECONDS = 300

logging.basicConfig(
    level=os.getenv('CANNO_LOG_LEVEL', 'INFO').upper(),
    format='%(asctime)s %(levelname)s %(message)s',
)
logger = logging.getLogger('canno')


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def now_dt():
    return datetime.now(TZ)


def now():
    return now_dt().isoformat()


def init_admin_password_hash():
    if ADMIN_PASSWORD_HASH:
        return ADMIN_PASSWORD_HASH
    if not ADMIN_PASSWORD:
        raise RuntimeError('Set CANNO_ADMIN_PASSWORD_HASH or CANNO_ADMIN_PASSWORD')
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', ADMIN_PASSWORD.encode(), salt.encode(), 200_000).hex()
    return f'pbkdf2_sha256$200000${salt}${digest}'


ADMIN_PASSWORD_HASH_VALUE = init_admin_password_hash()


def verify_password(raw_password, stored_hash):
    try:
        algo, iterations, salt, digest = stored_hash.split('$', 3)
        if algo != 'pbkdf2_sha256':
            return False
        candidate = hashlib.pbkdf2_hmac('sha256', raw_password.encode(), salt.encode(), int(iterations)).hex()
        return hmac.compare_digest(candidate, digest)
    except Exception:
        logger.error('Invalid password hash format')
        return False


def apply_migrations(conn):
    cur = conn.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)')
    version = cur.execute('SELECT COALESCE(MAX(version), 0) v FROM schema_migrations').fetchone()['v']

    if version < 1:
        cur.executescript('''
CREATE TABLE quests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  final_location TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  quest_time_limit_sec INTEGER
);
CREATE TABLE steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quest_id INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  prompt TEXT NOT NULL,
  password TEXT NOT NULL,
  step_time_limit_sec INTEGER,
  FOREIGN KEY(quest_id) REFERENCES quests(id)
);
CREATE TABLE participants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quest_id INTEGER NOT NULL,
  token TEXT NOT NULL UNIQUE,
  current_step INTEGER NOT NULL DEFAULT 1,
  started_at TEXT,
  step_started_at TEXT,
  locked_until TEXT,
  completed INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(quest_id) REFERENCES quests(id)
);
CREATE TABLE attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL,
  step_idx INTEGER NOT NULL,
  entered_password TEXT NOT NULL,
  success INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(participant_id) REFERENCES participants(id)
);
''')
        cur.execute('INSERT INTO schema_migrations(version, applied_at) VALUES (?,?)', (1, now()))
        logger.info('Applied migration v1')

    if version < 2:
        cur.execute("ALTER TABLE participants ADD COLUMN status TEXT NOT NULL DEFAULT 'new'")
        cur.execute('INSERT INTO schema_migrations(version, applied_at) VALUES (?,?)', (2, now()))
        logger.info('Applied migration v2')

    conn.commit()


def init_db():
    c = db()
    cur = c.cursor()
    apply_migrations(c)
    q = cur.execute('SELECT COUNT(*) c FROM quests').fetchone()['c']
    if q == 0:
        cur.execute('INSERT INTO quests(title, final_location, active, quest_time_limit_sec) VALUES (?,?,?,?)',
                    ('Демо-квест', 'Под стойкой у окна', 1, 3600))
        quest_id = cur.lastrowid
        steps = [
            (quest_id, 1, 'Найди бумажку возле входной двери и введи слово.', 'СОЛНЦЕ', 600),
            (quest_id, 2, 'Ищи под столом в переговорной.', 'ЛИСТ', 600),
            (quest_id, 3, 'Проверь полку с книгами.', 'МАЯК', 600),
            (quest_id, 4, 'Открой ящик с канцелярией.', 'КЛЮЧ', 600),
        ]
        cur.executemany('INSERT INTO steps(quest_id,idx,prompt,password,step_time_limit_sec) VALUES (?,?,?,?,?)', steps)
        token = secrets.token_urlsafe(8)
        cur.execute('INSERT INTO participants(quest_id, token, started_at, step_started_at) VALUES (?,?,?,?)',
                    (quest_id, token, now(), now()))
        c.commit()
        logger.info('Demo player URL: http://localhost:8000/play/%s', token)
    c.close()


def next_day_start_iso():
    n = now_dt()
    t = (n + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return t.isoformat()


def html(body):
    return f"""<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Canno Quest</title><link rel='stylesheet' href='/static.css'></head><body>{body}</body></html>"""


def error_page(code, title, message):
    return html(f"<main class='card'><h1>{code}: {html_lib.escape(title)}</h1><p>{html_lib.escape(message)}</p></main>")


def sanitize_text(raw, max_len=256):
    return raw.strip()[:max_len]


def parse_int(raw, default=None, minimum=None):
    raw = sanitize_text(raw, 32)
    if raw == '':
        return default
    if not raw.isdigit():
        return None
    value = int(raw)
    if minimum is not None and value < minimum:
        return None
    return value


class H(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logger.info('%s - %s', self.address_string(), format % args)

    def send_html(self, text, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(text.encode())

    def client_ip(self):
        return self.client_address[0]

    def parse_cookies(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get('Cookie', ''))
        return cookie

    def is_admin_authenticated(self):
        sid = self.parse_cookies().get(SESSION_COOKIE)
        if not sid:
            return False
        sid = sid.value
        expires_at = SESSIONS.get(sid)
        if not expires_at or expires_at < now_dt():
            SESSIONS.pop(sid, None)
            return False
        return True

    def require_admin(self):
        if self.is_admin_authenticated():
            return True
        self.send_response(303)
        self.send_header('Location', '/admin/login')
        self.end_headers()
        return False

    def _blocked(self, storage, key, max_attempts, window_seconds):
        attempts = storage.get(key, [])
        cutoff = now_dt() - timedelta(seconds=window_seconds)
        attempts = [ts for ts in attempts if ts > cutoff]
        storage[key] = attempts
        return len(attempts) >= max_attempts

    def _record_attempt(self, storage, key, window_seconds):
        attempts = storage.setdefault(key, [])
        cutoff = now_dt() - timedelta(seconds=window_seconds)
        attempts[:] = [ts for ts in attempts if ts > cutoff]
        attempts.append(now_dt())

    def do_GET(self):
        try:
            p = urlparse(self.path)
            if p.path == '/':
                self.send_html(html("<main class='card'><h1>Canno Quest</h1><p>Открой ссылку участника /play/&lt;token&gt; или админку /admin</p></main>")); return
            if p.path == '/static.css':
                css = Path('static.css').read_text(encoding='utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/css')
                self.end_headers()
                self.wfile.write(css.encode())
                return
            if p.path.startswith('/play/'):
                token = sanitize_text(p.path.split('/play/')[1], 128)
                self.render_play(token); return
            if p.path == '/admin/login':
                self.render_login(); return
            if p.path == '/admin/logout':
                self.logout(); return
            if p.path == '/admin':
                if not self.require_admin():
                    return
                self.render_admin(); return
            if p.path == '/admin/participants/export.csv':
                if not self.require_admin():
                    return
                self.export_participants_csv(); return
            if p.path == '/admin/metrics':
                if not self.require_admin():
                    return
                self.render_metrics(p.query); return
            if p.path == '/admin/quest/new':
                if not self.require_admin():
                    return
                self.render_quest_form(); return
            if p.path.startswith('/admin/quest/edit'):
                if not self.require_admin():
                    return
                quest_id = parse_int(parse_qs(p.query).get('id', [''])[0], minimum=1)
                if not quest_id:
                    self.send_html(error_page(400, 'Некорректные данные', 'id квеста обязателен'), 400); return
                self.render_quest_form(quest_id); return
            self.send_html(error_page(404, 'Не найдено', 'Страница не существует.'), 404)
        except Exception:
            logger.exception('Unhandled GET error')
            self.send_html(error_page(500, 'Ошибка сервера', 'Попробуйте снова позже.'), 500)

    def do_POST(self):
        try:
            p = urlparse(self.path)
            length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(length).decode(errors='ignore')
            data = parse_qs(raw_body)
            if p.path.startswith('/play/'):
                token = sanitize_text(p.path.split('/play/')[1], 128)
                self.submit_password(token, data.get('password', [''])[0]); return
            if p.path == '/admin/login':
                self.handle_login(data); return
            if p.path == '/admin/create-participant':
                if not self.require_admin():
                    return
                quest_id_raw = sanitize_text(data.get('quest_id', ['1'])[0], 16)
                if not quest_id_raw.isdigit():
                    self.send_html(error_page(400, 'Некорректные данные', 'quest_id должен быть числом'), 400)
                    return
                quest_id = int(quest_id_raw)
                token = secrets.token_urlsafe(8)
                c = db()
                c.execute('INSERT INTO participants(quest_id,token,started_at,step_started_at) VALUES (?,?,?,?)', (quest_id, token, now(), now()))
                c.commit()
                c.close()
                logger.info('Admin created participant token for quest_id=%s', quest_id)
                self.send_html(html(f"<main class='card'><p>Ссылка: <a href='/play/{token}'>/play/{token}</a></p><a href='/admin'>Назад</a></main>")); return
            if p.path == '/admin/create-participants-bulk':
                if not self.require_admin():
                    return
                self.create_participants_bulk(data); return
            if p.path == '/admin/participant/reset':
                if not self.require_admin():
                    return
                self.reset_participant(data); return
            if p.path == '/admin/quest/save':
                if not self.require_admin():
                    return
                self.save_quest(data); return
            if p.path == '/admin/quest/delete':
                if not self.require_admin():
                    return
                self.delete_quest(data); return
            if p.path == '/admin/quest/toggle-active':
                if not self.require_admin():
                    return
                self.toggle_quest_active(data); return
            self.send_json({'error': 'not found'}, 404)
        except Exception:
            logger.exception('Unhandled POST error')
            self.send_html(error_page(500, 'Ошибка сервера', 'Попробуйте снова позже.'), 500)

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())

    def render_login(self, error=''):
        err = f"<p class='error'>{html_lib.escape(error)}</p>" if error else ''
        self.send_html(html(f"<main class='card'><h1>Вход в админку</h1>{err}<form method='post'><input name='username' placeholder='Логин' maxlength='64' required><input type='password' name='password' maxlength='256' placeholder='Пароль' required><button>Войти</button></form></main>"))

    def handle_login(self, data):
        ip = self.client_ip()
        if self._blocked(LOGIN_ATTEMPTS, ip, MAX_LOGIN_ATTEMPTS, LOGIN_WINDOW_SECONDS):
            logger.warning('Login blocked for ip=%s', ip)
            self.render_login('Слишком много попыток. Повторите позже.')
            return
        username = sanitize_text(data.get('username', [''])[0], 64)
        password = sanitize_text(data.get('password', [''])[0], 256)
        if username == ADMIN_USER and verify_password(password, ADMIN_PASSWORD_HASH_VALUE):
            sid = secrets.token_urlsafe(32)
            SESSIONS[sid] = now_dt() + timedelta(hours=8)
            self.send_response(303)
            self.send_header('Location', '/admin')
            self.send_header('Set-Cookie', f'{SESSION_COOKIE}={sid}; HttpOnly; Path=/; SameSite=Lax')
            self.end_headers()
            logger.info('Admin login success from ip=%s', ip)
            return
        self._record_attempt(LOGIN_ATTEMPTS, ip, LOGIN_WINDOW_SECONDS)
        logger.warning('Admin login failed from ip=%s user=%s', ip, username)
        self.render_login('Неверный логин или пароль.')

    def logout(self):
        sid = self.parse_cookies().get(SESSION_COOKIE)
        if sid:
            SESSIONS.pop(sid.value, None)
        logger.info('Admin logout from ip=%s', self.client_ip())
        self.send_response(303)
        self.send_header('Location', '/admin/login')
        self.send_header('Set-Cookie', f'{SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0')
        self.end_headers()

    def render_play(self, token):
        c = db(); cur = c.cursor()
        p = cur.execute('SELECT * FROM participants WHERE token=?', (token,)).fetchone()
        if not p:
            logger.warning('Invalid participant token requested: token=%s ip=%s', token, self.client_ip())
            self.send_html(error_page(404, 'Ссылка недействительна', 'Проверьте URL.'), 404); return
        q = cur.execute('SELECT * FROM quests WHERE id=?', (p['quest_id'],)).fetchone()
        steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (p['quest_id'],)).fetchall()
        if not q['active']: self.send_html(html("<main class='card'><h2>Квест закрыт админом</h2></main>")); return
        if p['status'] == 'locked':
            self.send_html(html("<main class='card'><h2>Участник заблокирован администратором</h2></main>")); return
        if p['locked_until'] and datetime.fromisoformat(p['locked_until']) > now_dt():
            logger.info('Participant token=%s is locked until %s', token, p['locked_until'])
            self.send_html(html(f"<main class='card'><h2>До завтра недоступно</h2><p>Возвращайтесь после: {p['locked_until']}</p></main>")); return
        if p['completed']:
            cur.execute("UPDATE participants SET status='completed' WHERE id=?", (p['id'],))
            c.commit()
            self.send_html(html(f"<main class='card'><h2>Финиш!</h2><p>Приз находится: <b>{html_lib.escape(q['final_location'])}</b></p></main>")); return
        step = next((s for s in steps if s['idx'] == p['current_step']), None)
        if not step:
            self.send_html(error_page(500, 'Ошибка данных', 'Не найден текущий этап.'), 500)
            return
        progress = int((p['current_step'] - 1) / len(steps) * 100)
        self.send_html(html(f"""<main class='card'><h1>{html_lib.escape(q['title'])}</h1><div class='bar'><span style='width:{progress}%'></span></div><p>Этап {p['current_step']} из {len(steps)}</p><p>{html_lib.escape(step['prompt'])}</p><form method='post'><input name='password' placeholder='Введите пароль' maxlength='128' required><button>Проверить</button></form></main>"""))

    def submit_password(self, token, password):
        c = db(); cur = c.cursor(); p = cur.execute('SELECT * FROM participants WHERE token=?', (token,)).fetchone()
        if not p:
            logger.warning('POST to invalid participant token: token=%s ip=%s', token, self.client_ip())
            self.send_html(error_page(404, 'Ссылка недействительна', 'Проверьте URL.'), 404); return
        ip = self.client_ip()
        attempt_key = f'{ip}:{token}'
        if self._blocked(STEP_ATTEMPTS, attempt_key, MAX_STEP_ATTEMPTS, STEP_ATTEMPT_WINDOW_SECONDS):
            logger.warning('Step attempts rate-limited for token=%s ip=%s', token, ip)
            self.send_html(html("<main class='card'><p>Слишком много попыток. Подождите несколько минут.</p></main>"), 429)
            return
        steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (p['quest_id'],)).fetchall()
        q = cur.execute('SELECT * FROM quests WHERE id=?', (p['quest_id'],)).fetchone()
        step = next((s for s in steps if s['idx'] == p['current_step']), None)
        n = now_dt()
        if q['quest_time_limit_sec'] and p['started_at']:
            if n > datetime.fromisoformat(p['started_at']) + timedelta(seconds=q['quest_time_limit_sec']):
                logger.info('Quest timer expired for participant_id=%s token=%s', p['id'], token)
                cur.execute('UPDATE participants SET locked_until=? WHERE id=?', (next_day_start_iso(), p['id'])); c.commit(); self.send_html(html("<main class='card'><p>Время квеста вышло. До завтра.</p></main>")); return
        if step['step_time_limit_sec'] and p['step_started_at']:
            if n > datetime.fromisoformat(p['step_started_at']) + timedelta(seconds=step['step_time_limit_sec']):
                logger.info('Step timer expired for participant_id=%s token=%s step=%s', p['id'], token, p['current_step'])
                cur.execute('UPDATE participants SET locked_until=? WHERE id=?', (next_day_start_iso(), p['id'])); c.commit(); self.send_html(html("<main class='card'><p>Время этапа вышло. До завтра.</p></main>")); return
        cleaned_password = sanitize_text(password, 128)
        success = int(cleaned_password == step['password'])
        cur.execute('INSERT INTO attempts(participant_id,step_idx,entered_password,success,created_at) VALUES (?,?,?,?,?)', (p['id'], p['current_step'], cleaned_password, success, now()))
        if success:
            logger.info('Step solved for participant_id=%s token=%s step=%s', p['id'], token, p['current_step'])
            STEP_ATTEMPTS.pop(attempt_key, None)
            if p['current_step'] >= len(steps):
                cur.execute("UPDATE participants SET completed=1, status='completed' WHERE id=?", (p['id'],))
                logger.info('Quest completed for participant_id=%s token=%s', p['id'], token)
            else:
                cur.execute("UPDATE participants SET current_step=current_step+1, step_started_at=?, status='in_progress' WHERE id=?", (now(), p['id']))
            c.commit(); self.send_response(303); self.send_header('Location', f'/play/{token}'); self.end_headers(); return
        logger.warning('Wrong step password for participant_id=%s token=%s step=%s', p['id'], token, p['current_step'])
        self._record_attempt(STEP_ATTEMPTS, attempt_key, STEP_ATTEMPT_WINDOW_SECONDS)
        c.commit(); self.send_html(html(f"<main class='card'><p>Неверный пароль</p><a href='/play/{token}'>Назад</a></main>"))

    def render_admin(self):
        c = db(); cur = c.cursor(); quests = cur.execute('SELECT * FROM quests ORDER BY id DESC').fetchall(); parts = cur.execute('SELECT * FROM participants ORDER BY id DESC').fetchall()
        qopts = ''.join([f"<option value='{q['id']}'>{html_lib.escape(q['title'])}</option>" for q in quests if q['active']])
        rows = ''.join([f"<tr><td>{p['id']}</td><td><a href='/play/{p['token']}'>{p['token']}</a></td><td>{p['status']}</td><td>{p['current_step']}</td><td>{'да' if p['completed'] else 'нет'}</td><td>{p['locked_until'] or '-'}</td><td><form method='post' action='/admin/participant/reset'><input type='hidden' name='participant_id' value='{p['id']}'><button>Сброс</button></form></td></tr>" for p in parts])
        quest_rows = ''.join([
            f"<tr><td>{q['id']}</td><td>{html_lib.escape(q['title'])}</td><td>{'да' if q['active'] else 'нет'}</td>"
            f"<td><a href='/admin/quest/edit?id={q['id']}'>Редактировать</a></td>"
            f"<td><form method='post' action='/admin/quest/toggle-active'><input type='hidden' name='quest_id' value='{q['id']}'><button>{'Деактивировать' if q['active'] else 'Активировать'}</button></form></td></tr>"
            for q in quests
        ])
        self.send_html(html(f"<main class='card'><h1>Админка</h1><p><a href='/admin/logout'>Выйти</a> · <a href='/admin/metrics'>Метрики</a></p><p><a href='/admin/quest/new'>Создать квест</a></p><h2>Квесты</h2><table><tr><th>ID</th><th>Название</th><th>Активен</th><th></th><th></th></tr>{quest_rows}</table><form method='post' action='/admin/create-participant'><select name='quest_id'>{qopts}</select><button>Сгенерировать ссылку участника</button></form><form method='post' action='/admin/create-participants-bulk'><select name='quest_id'>{qopts}</select><input name='count' value='10' placeholder='Кол-во' maxlength='4'><button>Массово создать</button></form><p><a href='/admin/participants/export.csv'>Экспорт участников CSV</a></p><h2>Участники</h2><table><tr><th>ID</th><th>Token</th><th>Статус</th><th>Этап</th><th>Финиш</th><th>Блок до</th><th></th></tr>{rows}</table></main>"))

    def reset_participant(self, data):
        participant_id = parse_int(data.get('participant_id', [''])[0], minimum=1)
        if not participant_id:
            self.send_html(error_page(400, 'Некорректные данные', 'participant_id обязателен'), 400); return
        c = db(); cur = c.cursor()
        cur.execute("UPDATE participants SET current_step=1, started_at=?, step_started_at=?, locked_until=NULL, completed=0, status='new' WHERE id=?", (now(), now(), participant_id))
        c.commit()
        logger.info('Admin reset participant participant_id=%s', participant_id)
        self.send_response(303); self.send_header('Location', '/admin'); self.end_headers()

    def create_participants_bulk(self, data):
        quest_id = parse_int(data.get('quest_id', [''])[0], minimum=1)
        count = parse_int(data.get('count', [''])[0], default=10, minimum=1)
        if not quest_id or not count:
            self.send_html(error_page(400, 'Некорректные данные', 'quest_id/count обязательны'), 400); return
        count = min(count, 500)
        c = db(); cur = c.cursor()
        tokens = []
        for _ in range(count):
            token = secrets.token_urlsafe(8)
            tokens.append(token)
            cur.execute("INSERT INTO participants(quest_id,token,started_at,step_started_at,status) VALUES (?,?,?,?, 'new')", (quest_id, token, now(), now()))
        c.commit()
        links = ''.join([f"<li><a href='/play/{t}'>/play/{t}</a></li>" for t in tokens[:50]])
        suffix = "<p>Показаны первые 50 ссылок.</p>" if len(tokens) > 50 else ""
        logger.info('Admin bulk created participants quest_id=%s count=%s', quest_id, count)
        self.send_html(html(f"<main class='card'><h2>Создано: {count}</h2><ul>{links}</ul>{suffix}<a href='/admin'>Назад</a></main>"))

    def export_participants_csv(self):
        c = db(); cur = c.cursor()
        rows = cur.execute('SELECT id, quest_id, token, status, current_step, completed, started_at, step_started_at, locked_until FROM participants ORDER BY id').fetchall()
        lines = ['id,quest_id,token,status,current_step,completed,started_at,step_started_at,locked_until']
        for r in rows:
            lines.append(f"{r['id']},{r['quest_id']},{r['token']},{r['status']},{r['current_step']},{r['completed']},{r['started_at'] or ''},{r['step_started_at'] or ''},{r['locked_until'] or ''}")
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv; charset=utf-8')
        self.send_header('Content-Disposition', 'attachment; filename=participants.csv')
        self.end_headers()
        self.wfile.write('\n'.join(lines).encode('utf-8'))

    def render_metrics(self, query):
        period = sanitize_text(parse_qs(query).get('period', ['week'])[0], 16)
        days = {'day': 1, 'week': 7, 'month': 30}.get(period, 7)
        since = (now_dt() - timedelta(days=days)).isoformat()
        c = db(); cur = c.cursor()
        starts = cur.execute('SELECT COUNT(*) c FROM participants WHERE started_at >= ?', (since,)).fetchone()['c']
        completed = cur.execute('SELECT COUNT(*) c FROM participants WHERE completed=1 AND started_at >= ?', (since,)).fetchone()['c']
        avg_sec = cur.execute("SELECT AVG((julianday(a.created_at)-julianday(p.started_at))*86400.0) v FROM participants p JOIN attempts a ON a.participant_id=p.id WHERE p.completed=1 AND a.success=1 AND p.started_at >= ? GROUP BY p.id", (since,)).fetchall()
        avg_time = int(sum([r['v'] for r in avg_sec if r['v']]) / len(avg_sec)) if avg_sec else 0
        conv_rows = cur.execute('SELECT step_idx, COUNT(DISTINCT participant_id) c FROM attempts WHERE success=1 AND created_at >= ? GROUP BY step_idx ORDER BY step_idx', (since,)).fetchall()
        conv = defaultdict(int, {r['step_idx']: r['c'] for r in conv_rows})
        conv_html = ''.join([f"<tr><td>{idx}</td><td>{cnt}</td><td>{(cnt / starts * 100):.1f}%</td></tr>" for idx, cnt in conv.items()]) or "<tr><td colspan='3'>Нет данных</td></tr>"
        completion_rate = (completed / starts * 100) if starts else 0.0
        self.send_html(html(f"<main class='card'><h1>Метрики ({period})</h1><p><a href='/admin'>Назад</a></p><p>Стартов квеста: <b>{starts}</b></p><p>% завершения: <b>{completion_rate:.1f}%</b></p><p>Среднее время прохождения: <b>{avg_time} сек</b></p><h2>Конверсия по этапам</h2><table><tr><th>Этап</th><th>Прошли</th><th>Конверсия от стартов</th></tr>{conv_html}</table><p>Период: <a href='/admin/metrics?period=day'>день</a> · <a href='/admin/metrics?period=week'>неделя</a> · <a href='/admin/metrics?period=month'>месяц</a></p></main>"))

    def render_quest_form(self, quest_id=None):
        c = db()
        cur = c.cursor()
        quest = None
        steps = []
        if quest_id:
            quest = cur.execute('SELECT * FROM quests WHERE id=?', (quest_id,)).fetchone()
            if not quest:
                self.send_html(error_page(404, 'Не найдено', 'Квест не найден'), 404); return
            steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (quest_id,)).fetchall()
        steps_block = ''.join([
            f"<fieldset><legend>Этап {s['idx']}</legend><input name='step_{s['idx']}_prompt' value='{html_lib.escape(s['prompt'])}' placeholder='Подсказка' maxlength='256' required><input name='step_{s['idx']}_password' value='{html_lib.escape(s['password'])}' placeholder='Пароль' maxlength='128' required><input name='step_{s['idx']}_time' value='{s['step_time_limit_sec'] or ''}' placeholder='Лимит сек, опционально'></fieldset>"
            for s in steps
        ]) or "<p>Добавьте минимум 1 этап.</p>"
        delete_form = ""
        if quest_id:
            delete_form = f"<form method='post' action='/admin/quest/delete'><input type='hidden' name='quest_id' value='{quest_id}'><button>Удалить квест</button></form>"
        self.send_html(html(f"<main class='card'><h1>{'Редактирование' if quest_id else 'Новый'} квест</h1><form method='post' action='/admin/quest/save'><input type='hidden' name='quest_id' value='{quest_id or ''}'><input name='title' placeholder='Название' maxlength='128' value='{html_lib.escape(quest['title']) if quest else ''}' required><input name='final_location' placeholder='Финальная локация' maxlength='256' value='{html_lib.escape(quest['final_location']) if quest else ''}' required><input name='quest_time_limit_sec' placeholder='Лимит квеста в сек, опционально' value='{quest['quest_time_limit_sec'] if quest and quest['quest_time_limit_sec'] else ''}'>{steps_block}<textarea name='steps_new' placeholder='Новые этапы: подсказка|пароль|лимит_сек; по одному на строку'></textarea><button>Сохранить</button></form>{delete_form}<p><a href='/admin'>Назад</a></p></main>"))

    def save_quest(self, data):
        quest_id = parse_int(data.get('quest_id', [''])[0], minimum=1)
        title = sanitize_text(data.get('title', [''])[0], 128)
        final_location = sanitize_text(data.get('final_location', [''])[0], 256)
        quest_limit = parse_int(data.get('quest_time_limit_sec', [''])[0], default=None, minimum=1)
        if not title or not final_location:
            self.send_html(error_page(400, 'Некорректные данные', 'Нужны title и final_location'), 400); return
        c = db(); cur = c.cursor()
        if quest_id:
            cur.execute('UPDATE quests SET title=?, final_location=?, quest_time_limit_sec=? WHERE id=?', (title, final_location, quest_limit, quest_id))
        else:
            cur.execute('INSERT INTO quests(title, final_location, active, quest_time_limit_sec) VALUES (?,?,1,?)', (title, final_location, quest_limit))
            quest_id = cur.lastrowid
        existing_steps = cur.execute('SELECT idx FROM steps WHERE quest_id=? ORDER BY idx', (quest_id,)).fetchall()
        for row in existing_steps:
            idx = row['idx']
            prompt = sanitize_text(data.get(f'step_{idx}_prompt', [''])[0], 256)
            password = sanitize_text(data.get(f'step_{idx}_password', [''])[0], 128)
            step_limit = parse_int(data.get(f'step_{idx}_time', [''])[0], default=None, minimum=1)
            if prompt and password:
                cur.execute('UPDATE steps SET prompt=?, password=?, step_time_limit_sec=? WHERE quest_id=? AND idx=?', (prompt, password, step_limit, quest_id, idx))
        new_steps_raw = data.get('steps_new', [''])[0]
        for line in new_steps_raw.splitlines():
            chunks = [sanitize_text(x, 256) for x in line.split('|')]
            if len(chunks) < 2 or not chunks[0] or not chunks[1]:
                continue
            step_limit = parse_int(chunks[2] if len(chunks) > 2 else '', default=None, minimum=1)
            next_idx = cur.execute('SELECT COALESCE(MAX(idx), 0) m FROM steps WHERE quest_id=?', (quest_id,)).fetchone()['m'] + 1
            cur.execute('INSERT INTO steps(quest_id,idx,prompt,password,step_time_limit_sec) VALUES (?,?,?,?,?)', (quest_id, next_idx, chunks[0], chunks[1], step_limit))
        c.commit()
        logger.info('Admin saved quest quest_id=%s', quest_id)
        self.send_response(303); self.send_header('Location', '/admin'); self.end_headers()

    def delete_quest(self, data):
        quest_id = parse_int(data.get('quest_id', [''])[0], minimum=1)
        if not quest_id:
            self.send_html(error_page(400, 'Некорректные данные', 'quest_id обязателен'), 400); return
        c = db(); cur = c.cursor()
        cur.execute('DELETE FROM attempts WHERE participant_id IN (SELECT id FROM participants WHERE quest_id=?)', (quest_id,))
        cur.execute('DELETE FROM participants WHERE quest_id=?', (quest_id,))
        cur.execute('DELETE FROM steps WHERE quest_id=?', (quest_id,))
        cur.execute('DELETE FROM quests WHERE id=?', (quest_id,))
        c.commit()
        logger.warning('Admin deleted quest quest_id=%s', quest_id)
        self.send_response(303); self.send_header('Location', '/admin'); self.end_headers()

    def toggle_quest_active(self, data):
        quest_id = parse_int(data.get('quest_id', [''])[0], minimum=1)
        if not quest_id:
            self.send_html(error_page(400, 'Некорректные данные', 'quest_id обязателен'), 400); return
        c = db(); cur = c.cursor()
        quest = cur.execute('SELECT * FROM quests WHERE id=?', (quest_id,)).fetchone()
        if not quest:
            self.send_html(error_page(404, 'Не найдено', 'Квест не найден'), 404); return
        if quest['active']:
            active_players = cur.execute('SELECT COUNT(*) c FROM participants WHERE quest_id=? AND completed=0', (quest_id,)).fetchone()['c']
            if active_players > 0:
                self.send_html(error_page(409, 'Нельзя деактивировать', 'Есть активные участники в процессе.'), 409); return
        cur.execute('UPDATE quests SET active=? WHERE id=?', (0 if quest['active'] else 1, quest_id))
        c.commit()
        logger.info('Admin toggled quest active=%s quest_id=%s', 0 if quest['active'] else 1, quest_id)
        self.send_response(303); self.send_header('Location', '/admin'); self.end_headers()


if __name__ == '__main__':
    init_db()
    logger.info('Starting HTTP server on 0.0.0.0:8000')
    HTTPServer(('0.0.0.0', 8000), H).serve_forever()
