import html as html_lib
import json
import logging
import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from canno import config
from canno.templates.html import error_page, html


logger = logging.getLogger('canno')


def create_handler(repo, service, admin_password_hash_value):
    class H(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            logger.info('%s - %s', self.address_string(), format % args)

        def send_html(self, text, status=200):
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(text.encode())

        def send_json(self, data, status=200):
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode())

        def client_ip(self):
            return self.client_address[0]

        def parse_cookies(self):
            cookie = SimpleCookie()
            cookie.load(self.headers.get('Cookie', ''))
            return cookie

        def is_admin_authenticated(self):
            sid = self.parse_cookies().get(config.SESSION_COOKIE)
            if not sid:
                return False
            sid = sid.value
            expires_at = service.sessions.get(sid)
            if not expires_at or expires_at < service.now_dt():
                service.sessions.pop(sid, None)
                return False
            return True

        def require_admin(self):
            if self.is_admin_authenticated():
                return True
            self.send_response(303)
            self.send_header('Location', '/admin/login')
            self.end_headers()
            return False

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
                    token = service.sanitize_text(p.path.split('/play/')[1], 128)
                    self.render_play(token); return
                if p.path == '/admin/login':
                    self.render_login(); return
                if p.path == '/admin/logout':
                    self.logout(); return
                if p.path == '/admin':
                    if not self.require_admin(): return
                    self.render_admin(); return
                if p.path == '/admin/participants/export.csv':
                    if not self.require_admin(): return
                    self.export_participants_csv(); return
                if p.path == '/admin/metrics':
                    if not self.require_admin(): return
                    self.render_metrics(p.query); return
                if p.path == '/admin/quest/new':
                    if not self.require_admin(): return
                    self.render_quest_form(); return
                if p.path.startswith('/admin/quest/edit'):
                    if not self.require_admin(): return
                    quest_id = service.parse_int(parse_qs(p.query).get('id', [''])[0], minimum=1)
                    if not quest_id:
                        self.send_html(error_page(400, 'Некорректные данные', 'id квеста обязателен'), 400); return
                    self.render_quest_form(quest_id); return
                self.send_html(error_page(404, 'Не найдено', 'Страница не существует.'), 404)
            except Exception:
                logger.exception('Unhandled GET error')
                self.send_html(error_page(500, 'Ошибка сервера', 'Попробуйте снова позже.'), 500)

        def do_POST(self):
            p = urlparse(self.path)
            length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(length).decode(errors='ignore')
            data = parse_qs(raw_body)
            if p.path == '/admin/login':
                return self.handle_login(data)
            if p.path.startswith('/play/'):
                return self.submit_password(service.sanitize_text(p.path.split('/play/')[1], 128), data.get('password', [''])[0])
            self.send_json({'error': 'not found'}, 404)

        def render_login(self, error=''):
            err = f"<p class='error'>{html_lib.escape(error)}</p>" if error else ''
            self.send_html(html(f"<main class='card'><h1>Вход в админку</h1>{err}<form method='post'><input name='username' placeholder='Логин' maxlength='64' required><input type='password' name='password' maxlength='256' placeholder='Пароль' required><button>Войти</button></form></main>"))

        def handle_login(self, data):
            ip = self.client_ip()
            if service.blocked(service.login_attempts, ip, config.MAX_LOGIN_ATTEMPTS, config.LOGIN_WINDOW_SECONDS):
                self.render_login('Слишком много попыток. Повторите позже.'); return
            username = service.sanitize_text(data.get('username', [''])[0], 64)
            password = service.sanitize_text(data.get('password', [''])[0], 256)
            if username == config.ADMIN_USER and service.verify_password(password, admin_password_hash_value):
                sid = secrets.token_urlsafe(32)
                service.sessions[sid] = service.now_dt() + timedelta(hours=8)
                self.send_response(303)
                self.send_header('Location', '/admin')
                self.send_header('Set-Cookie', f'{config.SESSION_COOKIE}={sid}; HttpOnly; Path=/; SameSite=Lax')
                self.end_headers()
                return
            service.record_attempt(service.login_attempts, ip, config.LOGIN_WINDOW_SECONDS)
            self.render_login('Неверный логин или пароль.')

        def logout(self):
            sid = self.parse_cookies().get(config.SESSION_COOKIE)
            if sid: service.sessions.pop(sid.value, None)
            self.send_response(303)
            self.send_header('Location', '/admin/login')
            self.send_header('Set-Cookie', f'{config.SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0')
            self.end_headers()

        def render_play(self, token):
            c = repo.connect(); cur = c.cursor()
            p = cur.execute('SELECT * FROM participants WHERE token=?', (token,)).fetchone()
            if not p: self.send_html(error_page(404, 'Ссылка недействительна', 'Проверьте URL.'), 404); return
            q = cur.execute('SELECT * FROM quests WHERE id=?', (p['quest_id'],)).fetchone()
            steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (p['quest_id'],)).fetchall()
            if not q['active']: self.send_html(html("<main class='card'><h2>Квест закрыт админом</h2></main>")); return
            step = next((s for s in steps if s['idx'] == p['current_step']), None)
            progress = int((p['current_step'] - 1) / len(steps) * 100)
            self.send_html(html(f"""<main class='card'><h1>{html_lib.escape(q['title'])}</h1><div class='bar'><span style='width:{progress}%'></span></div><p>Этап {p['current_step']} из {len(steps)}</p><p>{html_lib.escape(step['prompt'])}</p><form method='post'><input name='password' placeholder='Введите пароль' maxlength='128' required><button>Проверить</button></form></main>"""))

        def submit_password(self, token, password):
            c = repo.connect(); cur = c.cursor(); p = cur.execute('SELECT * FROM participants WHERE token=?', (token,)).fetchone()
            if not p: self.send_html(error_page(404, 'Ссылка недействительна', 'Проверьте URL.'), 404); return
            ip = self.client_ip(); key = f'{ip}:{token}'
            if service.blocked(service.step_attempts, key, config.MAX_STEP_ATTEMPTS, config.STEP_ATTEMPT_WINDOW_SECONDS):
                self.send_html(html("<main class='card'><p>Слишком много попыток. Подождите несколько минут.</p></main>"), 429); return
            steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (p['quest_id'],)).fetchall()
            step = next((s for s in steps if s['idx'] == p['current_step']), None)
            cleaned = service.sanitize_text(password, 128)
            success = int(cleaned == step['password'])
            cur.execute('INSERT INTO attempts(participant_id,step_idx,entered_password,success,created_at) VALUES (?,?,?,?,?)', (p['id'], p['current_step'], cleaned, success, service.now()))
            if success:
                service.step_attempts.pop(key, None)
                if p['current_step'] >= len(steps):
                    cur.execute("UPDATE participants SET completed=1, status='completed' WHERE id=?", (p['id'],))
                else:
                    cur.execute("UPDATE participants SET current_step=current_step+1, step_started_at=?, status='in_progress' WHERE id=?", (service.now(), p['id']))
                c.commit(); self.send_response(303); self.send_header('Location', f'/play/{token}'); self.end_headers(); return
            service.record_attempt(service.step_attempts, key, config.STEP_ATTEMPT_WINDOW_SECONDS)
            c.commit(); self.send_html(html(f"<main class='card'><p>Неверный пароль</p><a href='/play/{token}'>Назад</a></main>"))

        def render_admin(self):
            self.send_html(html("<main class='card'><h1>Админка</h1></main>"))

        def export_participants_csv(self):
            self.send_response(200); self.end_headers()

        def render_metrics(self, query):
            self.send_html(html("<main class='card'><h1>Метрики</h1></main>"))

        def render_quest_form(self, quest_id=None):
            self.send_html(html("<main class='card'><h1>Квест</h1></main>"))

    return H
