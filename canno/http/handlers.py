import html as html_lib
import json
import logging
import secrets
import csv
import io
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from canno import config
from canno.templates.html import error_page, html


logger = logging.getLogger('canno')


def create_handler(repo, service, admin_password_hash_value, auth_store):
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

        def send_csv(self, filename, content):
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))

        def client_ip(self):
            return self.client_address[0]

        def audit(self, actor, action, target='', metadata=None, ip=None):
            c = repo.connect()
            try:
                c.execute(
                    'INSERT INTO audit_events(created_at, actor, action, target, metadata, ip) VALUES (?,?,?,?,?,?)',
                    (
                        service.now(),
                        actor,
                        action,
                        service.sanitize_text(target, 512),
                        json.dumps(metadata or {}, ensure_ascii=False),
                        ip or self.client_ip(),
                    ),
                )
                c.commit()
            finally:
                c.close()

        def parse_cookies(self):
            cookie = SimpleCookie()
            cookie.load(self.headers.get('Cookie', ''))
            return cookie

        def is_admin_authenticated(self):
            sid = self.parse_cookies().get(config.SESSION_COOKIE)
            if not sid:
                return False
            sid = sid.value
            expires_at = auth_store.get(sid)
            if not expires_at or expires_at < service.now_dt():
                auth_store.delete(sid)
                return False
            return True

        def _blocked(self, bucket, key, max_attempts, window_seconds):
            cutoff = service.now_dt() - timedelta(seconds=window_seconds)
            return auth_store.get_attempts_since(bucket, key, cutoff) >= max_attempts

        def _record_attempt(self, bucket, key):
            auth_store.add_attempt(bucket, key, service.now_dt())

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
                if p.path == '/admin/audit':
                    if not self.require_admin(): return
                    self.render_audit(p.query); return
                if p.path == '/admin/audit/export.csv':
                    if not self.require_admin(): return
                    self.export_audit_csv(p.query); return
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
            if self._blocked("login", ip, config.MAX_LOGIN_ATTEMPTS, config.LOGIN_WINDOW_SECONDS):
                self.render_login('Слишком много попыток. Повторите позже.'); return
            username = service.sanitize_text(data.get('username', [''])[0], 64)
            password = service.sanitize_text(data.get('password', [''])[0], 256)
            if username == config.ADMIN_USER and service.verify_password(password, admin_password_hash_value):
                sid = secrets.token_urlsafe(32)
                auth_store.set(sid, service.now_dt() + timedelta(hours=8))
                self.audit('admin', 'admin.login.success', target=username, metadata={'session_id': sid}, ip=ip)
                self.send_response(303)
                self.send_header('Location', '/admin')
                self.send_header('Set-Cookie', f'{config.SESSION_COOKIE}={sid}; HttpOnly; Path=/; SameSite=Lax')
                self.end_headers()
                return
            self._record_attempt("login", ip)
            self.audit('admin', 'admin.login.failed', target=username, metadata={'reason': 'invalid_credentials'}, ip=ip)
            self.render_login('Неверный логин или пароль.')

        def format_seconds(self, total_seconds):
            secs = max(0, int(total_seconds))
            minutes, seconds = divmod(secs, 60)
            return f"{minutes:02d}:{seconds:02d}"

        def player_hint(self, step_idx):
            hints = {
                1: 'Подумайте про предмет, который открывает замки.',
                2: 'Это предмет освещения, который обычно висит на потолке.',
                3: 'Ищите вещь, с которой вы обычно на связи.',
                4: 'Это место для хранения документов и ценных бумаг.',
            }
            return hints.get(step_idx, 'Внимательно перечитайте загадку и попробуйте другой вариант.')

        def logout(self):
            sid = self.parse_cookies().get(config.SESSION_COOKIE)
            if sid:
                auth_store.delete(sid.value)
                self.audit('admin', 'admin.logout', metadata={'session_id': sid.value})
            self.send_response(303)
            self.send_header('Location', '/admin/login')
            self.send_header('Set-Cookie', f'{config.SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0')
            self.end_headers()

        def render_play(self, token):
            c = repo.connect(); cur = c.cursor()
            try:
                p = cur.execute('SELECT * FROM participants WHERE token=?', (token,)).fetchone()
                if not p: self.send_html(error_page(404, 'Ссылка недействительна', 'Проверьте URL.'), 404); return
                q = cur.execute('SELECT * FROM quests WHERE id=?', (p['quest_id'],)).fetchone()
                steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (p['quest_id'],)).fetchall()
                if not q['active']: self.send_html(html("<main class='card'><h2>Квест временно закрыт</h2><p>Свяжитесь с организатором и попробуйте позже.</p></main>")); return
                step = next((s for s in steps if s['idx'] == p['current_step']), None)
                progress = int((p['current_step'] - 1) / len(steps) * 100)
                remaining_html = ''
                if step and step['step_time_limit_sec'] and p['step_started_at']:
                    started_at = datetime.fromisoformat(p['step_started_at'])
                    deadline = started_at + timedelta(seconds=step['step_time_limit_sec'])
                    remaining = (deadline - service.now_dt()).total_seconds()
                    remaining_html = f"<div class='timer-wrap'><p class='muted'>Осталось времени на этап</p><p id='step-timer' class='timer' data-remaining='{int(remaining)}' data-warning='120'>{self.format_seconds(remaining)}</p><p id='step-warning' class='warning hidden'>Мало времени — попробуйте самый очевидный вариант ответа.</p></div>"
                self.send_html(html(f"""<main class='card'><h1>{html_lib.escape(q['title'])}</h1><div class='bar'><span style='width:{progress}%'></span></div><p class='muted'>Этап {p['current_step']} из {len(steps)}</p>{remaining_html}<p class='prompt'>{html_lib.escape(step['prompt'])}</p><form method='post'><input name='password' placeholder='Введите пароль' maxlength='128' autocomplete='off' required><button>Проверить ответ</button></form></main><script>const timer=document.getElementById('step-timer');if(timer){{let remaining=Number(timer.dataset.remaining||0);const warningAt=Number(timer.dataset.warning||120);const warning=document.getElementById('step-warning');const fmt=(n)=>{{const s=Math.max(0,Math.floor(n));const m=String(Math.floor(s/60)).padStart(2,'0');const sec=String(s%60).padStart(2,'0');return m+':'+sec;}};const tick=()=>{{timer.textContent=fmt(remaining);if(remaining<=warningAt&&warning){{warning.classList.remove('hidden');timer.classList.add('timer-danger');}}if(remaining<=0){{clearInterval(iv);}}remaining-=1;}};tick();const iv=setInterval(tick,1000);}}</script>"""))
            finally:
                c.close()

        def submit_password(self, token, password):
            c = repo.connect(); cur = c.cursor()
            try:
                p = cur.execute('SELECT * FROM participants WHERE token=?', (token,)).fetchone()
                if not p: self.send_html(error_page(404, 'Ссылка недействительна', 'Проверьте URL.'), 404); return
                ip = self.client_ip(); key = f'{ip}:{token}'
                if self._blocked("step", key, config.MAX_STEP_ATTEMPTS, config.STEP_ATTEMPT_WINDOW_SECONDS):
                    self.audit('player', 'participant.blocked', target=f'participant:{p["id"]}', metadata={'participant_id': p['id'], 'token': token})
                    self.send_html(html("<main class='card'><p>Слишком много попыток. Подождите несколько минут.</p></main>"), 429); return
                steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (p['quest_id'],)).fetchall()
                step = next((s for s in steps if s['idx'] == p['current_step']), None)
                cleaned = service.sanitize_text(password, 128)
                success = int(cleaned == step['password'])
                cur.execute('INSERT INTO attempts(participant_id,step_idx,entered_password,success,created_at) VALUES (?,?,?,?,?)', (p['id'], p['current_step'], cleaned, success, service.now()))
                if success:
                    auth_store.clear_attempts("step", key)
                    if p['current_step'] >= len(steps):
                        cur.execute("UPDATE participants SET completed=1, status='completed' WHERE id=?", (p['id'],))
                        self.audit('player', 'participant.completion', target=f'participant:{p["id"]}', metadata={'participant_id': p['id'], 'token': token, 'quest_id': p['quest_id']})
                    else:
                        cur.execute("UPDATE participants SET current_step=current_step+1, step_started_at=?, status='in_progress' WHERE id=?", (service.now(), p['id']))
                    c.commit(); self.send_response(303); self.send_header('Location', f'/play/{token}'); self.end_headers(); return
                c.commit()
                self._record_attempt("step", key)
                hint = self.player_hint(p['current_step'])
                self.send_html(html(f"<main class='card'><h2>Пока не подошло</h2><p>Неверный пароль. Проверьте раскладку клавиатуры и попробуйте ещё раз.</p><p class='hint'>Подсказка: {html_lib.escape(hint)}</p><a href='/play/{token}'>Вернуться к этапу</a></main>"))
            finally:
                c.close()

        def render_admin(self):
            self.send_html(html("<main class='card'><h1>Админка</h1><p><a href='/admin/audit'>Журнал аудита</a></p></main>"))

        def export_participants_csv(self):
            self.send_response(200); self.end_headers()

        def render_metrics(self, query):
            self.send_html(html("<main class='card'><h1>Метрики</h1></main>"))

        def render_quest_form(self, quest_id=None):
            self.audit('admin', 'admin.quest.form.view', target=f'quest:{quest_id or "new"}', metadata={'quest_id': quest_id})
            self.send_html(html("<main class='card'><h1>Квест</h1></main>"))

        def render_audit(self, query):
            params = parse_qs(query)
            action = service.sanitize_text(params.get('action', [''])[0], 128)
            quest_id = service.parse_int(params.get('quest_id', [''])[0], minimum=1)
            date_from = service.sanitize_text(params.get('from', [''])[0], 64)
            date_to = service.sanitize_text(params.get('to', [''])[0], 64)
            sql = 'SELECT * FROM audit_events WHERE 1=1'
            vals = []
            if action:
                sql += ' AND action=?'
                vals.append(action)
            if quest_id:
                sql += " AND metadata LIKE ?"
                vals.append(f'%\"quest_id\": {quest_id}%')
            if date_from:
                sql += ' AND created_at>=?'
                vals.append(date_from)
            if date_to:
                sql += ' AND created_at<=?'
                vals.append(date_to)
            sql += ' ORDER BY id DESC LIMIT 300'
            c = repo.connect()
            rows = c.execute(sql, tuple(vals)).fetchall()
            c.close()
            items = ''.join(
                f"<tr><td>{html_lib.escape(r['created_at'])}</td><td>{html_lib.escape(r['actor'])}</td><td>{html_lib.escape(r['action'])}</td><td>{html_lib.escape(r['target'] or '')}</td><td><pre>{html_lib.escape(r['metadata'] or '')}</pre></td><td>{html_lib.escape(r['ip'] or '')}</td></tr>"
                for r in rows
            )
            export_link = f"/admin/audit/export.csv?action={action}&quest_id={quest_id or ''}&from={date_from}&to={date_to}"
            self.send_html(html(f"<main class='card'><h1>Аудит</h1><form><input name='from' placeholder='from ISO' value='{html_lib.escape(date_from)}'><input name='to' placeholder='to ISO' value='{html_lib.escape(date_to)}'><input name='action' placeholder='action' value='{html_lib.escape(action)}'><input name='quest_id' placeholder='quest_id' value='{quest_id or ''}'><button>Фильтр</button></form><p><a href='{html_lib.escape(export_link)}'>Экспорт CSV</a></p><table><tr><th>Время</th><th>Actor</th><th>Action</th><th>Target</th><th>Metadata</th><th>IP</th></tr>{items}</table></main>"))

        def export_audit_csv(self, query):
            params = parse_qs(query)
            action = service.sanitize_text(params.get('action', [''])[0], 128)
            quest_id = service.parse_int(params.get('quest_id', [''])[0], minimum=1)
            sql = 'SELECT created_at, actor, action, target, metadata, ip FROM audit_events WHERE 1=1'
            vals = []
            if action:
                sql += ' AND action=?'
                vals.append(action)
            if quest_id:
                sql += " AND metadata LIKE ?"
                vals.append(f'%\"quest_id\": {quest_id}%')
            sql += ' ORDER BY id DESC LIMIT 10000'
            c = repo.connect()
            rows = c.execute(sql, tuple(vals)).fetchall()
            c.close()
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['created_at', 'actor', 'action', 'target', 'metadata', 'ip'])
            for row in rows:
                writer.writerow([row['created_at'], row['actor'], row['action'], row['target'], row['metadata'], row['ip']])
            self.send_csv('audit_events.csv', output.getvalue())

    return H
