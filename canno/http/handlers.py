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
BASE_DIR = Path(__file__).resolve().parents[2]


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

        def get_user_role(self):
            sid = self.parse_cookies().get(config.SESSION_COOKIE)
            if not sid:
                return None
            sid = sid.value
            session = auth_store.get(sid)
            if not session or session['expires_at'] < service.now_dt():
                auth_store.delete(sid)
                return None
            return session['role']

        def _blocked(self, bucket, key, max_attempts, window_seconds):
            cutoff = service.now_dt() - timedelta(seconds=window_seconds)
            return auth_store.get_attempts_since(bucket, key, cutoff) >= max_attempts

        def _record_attempt(self, bucket, key):
            auth_store.add_attempt(bucket, key, service.now_dt())

        def require_admin(self):
            if self.get_user_role() == 'admin':
                return True
            self.send_response(303)
            self.send_header('Location', '/admin/login')
            self.end_headers()
            return False

        def require_editor(self):
            if self.get_user_role() in ('admin', 'editor'):
                return True
            self.send_response(303)
            self.send_header('Location', '/admin/login')
            self.end_headers()
            return False

        def is_english_enabled(self):
            c = repo.connect()
            try:
                row = c.execute("SELECT value FROM app_settings WHERE key='enable_english_content'").fetchone()
                return bool(row and row['value'] == '1')
            except Exception:
                return False
            finally:
                c.close()

        def get_app_setting(self, key, default=''):
            c = repo.connect()
            try:
                row = c.execute("SELECT value FROM app_settings WHERE key=?", (key,)).fetchone()
                return row['value'] if row else default
            except Exception:
                return default
            finally:
                c.close()

        def do_GET(self):
            try:
                p = urlparse(self.path)
                if p.path == '/':
                    self.render_home(); return
                if p.path in ('/static.css', '/static/style.css'):
                    css = (BASE_DIR / 'static' / 'style.css').read_text(encoding='utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/css')
                    self.end_headers()
                    self.wfile.write(css.encode())
                    return
                if p.path in ('/logo.png', '/logo1.png', '/static/images/logo1.png'):
                    logo_rel_path = self.get_app_setting('homepage_logo_path', 'static/images/logo1.png') or 'static/images/logo1.png'
                    logo = (BASE_DIR / logo_rel_path).resolve()
                    try:
                        logo.relative_to(BASE_DIR.resolve())
                    except Exception:
                        self.send_html(error_page(400, 'Некорректные данные', 'Путь к логотипу должен быть внутри проекта.'), 400); return
                    if not logo.exists():
                        self.send_html(error_page(404, 'Не найдено', 'Логотип не найден.'), 404); return
                    self.send_response(200)
                    self.send_header('Content-Type', 'image/png')
                    self.end_headers()
                    self.wfile.write(logo.read_bytes())
                    return
                if p.path.startswith('/play/'):
                    token = service.sanitize_text(p.path.split('/play/')[1], 128)
                    self.render_play(token); return
                if p.path == '/admin/login':
                    if self.get_user_role() == 'admin':
                        self.send_response(303); self.send_header('Location', '/admin'); self.end_headers(); return
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
                    if not self.require_editor(): return
                    self.send_response(303); self.send_header('Location', '/admin/quest/edit'); self.end_headers(); return
                if p.path == '/admin/quest/edit':
                    if not self.require_editor(): return
                    quest_id = service.parse_int(parse_qs(p.query).get('id', [''])[0], minimum=1)
                    self.render_quest_form(quest_id); return
                if p.path == '/admin/quests/export.json':
                    if not self.require_admin(): return
                    self.export_quests_json(); return
                if p.path == '/admin/settings':
                    if not self.require_admin(): return
                    self.render_admin_settings(); return
                if p.path == '/admin/runs/archive':
                    if not self.require_admin(): return
                    self.archive_completed_runs(); return
                self.send_html(error_page(404, 'Не найдено', 'Страница не существует.'), 404)
            except Exception as exc:
                logger.exception('Unhandled GET error on path %s', self.path)
                debug_hint = f"Техническая информация: {type(exc).__name__}: {html_lib.escape(str(exc))}"
                self.send_html(error_page(500, 'Ошибка сервера', f'Попробуйте снова позже. {debug_hint}'), 500)

        def do_POST(self):
            p = urlparse(self.path)
            length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(length).decode(errors='ignore')
            data = parse_qs(raw_body)
            if p.path == '/admin/login':
                return self.handle_login(data)
            if p.path == '/admin/quests/import':
                if not self.require_admin(): return
                return self.import_quest_json(data)
            if p.path == '/admin/editors/save':
                if not self.require_admin(): return
                return self.save_editor_account(data)
            if p.path == '/admin/settings/save':
                if not self.require_admin(): return
                return self.save_admin_settings(data)
            if p.path == '/admin/quest/save':
                if not self.require_editor(): return
                return self.save_quest_settings(data)
            if p.path == '/admin/quest/toggle':
                if not self.require_editor(): return
                return self.toggle_quest(data)
            if p.path.startswith('/play/'):
                return self.submit_password(service.sanitize_text(p.path.split('/play/')[1], 128), data.get('password', [''])[0])
            self.send_json({'error': 'not found'}, 404)

        def render_login(self, error=''):
            err = f"<p class='error'>{html_lib.escape(error)}</p>" if error else ''
            self.send_html(html(f"<main class='card auth-card screen-login'><h1 class='auth-title'>Вход в панель управления</h1>{err}<form method='post' class='form-stack'><input name='username' placeholder='Логин' maxlength='64' required><input type='password' name='password' maxlength='256' placeholder='Пароль' required><button class='btn'>Войти</button></form></main>"))

        def resolve_user(self, username):
            if username == config.ADMIN_USER:
                return {'role': 'admin', 'username': config.ADMIN_USER, 'password_hash': admin_password_hash_value}
            c = repo.connect()
            try:
                row = c.execute('SELECT username, password_hash FROM editor_accounts WHERE username=? AND is_active=1', (username,)).fetchone()
                if row:
                    return {'role': 'editor', 'username': row['username'], 'password_hash': row['password_hash']}
            finally:
                c.close()
            if username == config.EDITOR_USER:
                return {
                    'role': 'editor',
                    'username': config.EDITOR_USER,
                    'password_hash': service.resolve_password_hash(config.EDITOR_PASSWORD_HASH, config.EDITOR_PASSWORD),
                }
            return None

        def handle_login(self, data):
            ip = self.client_ip()
            if self._blocked("login", ip, config.MAX_LOGIN_ATTEMPTS, config.LOGIN_WINDOW_SECONDS):
                self.render_login('Слишком много попыток. Повторите позже.'); return
            username = service.sanitize_text(data.get('username', [''])[0], 64)
            password = service.sanitize_text(data.get('password', [''])[0], 256)
            user = self.resolve_user(username)
            if user and service.verify_password(password, user['password_hash']):
                sid = secrets.token_urlsafe(32)
                auth_store.set(sid, service.now_dt() + timedelta(hours=8), role=user['role'])
                self.audit(user['role'], f"{user['role']}.login.success", target=username, metadata={'session_id': sid}, ip=ip)
                self.send_response(303)
                self.send_header('Location', '/admin' if user['role'] == 'admin' else '/admin/quest/edit')
                self.send_header('Set-Cookie', f'{config.SESSION_COOKIE}={sid}; HttpOnly; Path=/; Max-Age=28800; SameSite=Lax')
                self.end_headers()
                return
            self._record_attempt("login", ip)
            self.audit('auth', 'login.failed', target=username, metadata={'reason': 'invalid_credentials'}, ip=ip)
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

        def parse_duration_seconds(self, amount_raw, unit_raw, fallback_raw=''):
            amount = service.parse_int(amount_raw, minimum=0)
            if amount is None:
                return service.parse_int(fallback_raw, minimum=0)
            unit = service.sanitize_text(unit_raw or 'minutes', 16)
            return amount * (3600 if unit == 'hours' else 60)

        def format_limit_label(self, total_seconds):
            secs = service.parse_int(total_seconds, minimum=0) or 0
            if secs == 0:
                return '—'
            if secs % 3600 == 0:
                return f'{secs // 3600} ч'
            if secs % 60 == 0:
                return f'{secs // 60} мин'
            return f'{secs / 60:.1f} мин'

        def generate_quest_code(self, cur):
            alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
            for _ in range(20):
                code = ''.join(secrets.choice(alphabet) for _ in range(4))
                if not cur.execute('SELECT id FROM quests WHERE access_code=?', (code,)).fetchone():
                    return code
            raise RuntimeError('Не удалось сгенерировать уникальный код квеста')

        def logout(self):
            sid = self.parse_cookies().get(config.SESSION_COOKIE)
            if sid:
                auth_store.delete(sid.value)
                self.audit('admin', 'admin.logout', metadata={'session_id': sid.value})
            self.send_response(303)
            self.send_header('Location', '/admin/login')
            self.send_header('Set-Cookie', f'{config.SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0')
            self.end_headers()

        def get_homepage_intro(self):
            c = repo.connect(); cur = c.cursor()
            try:
                row = cur.execute("SELECT value FROM site_settings WHERE key='homepage_intro'").fetchone()
                if row and row['value']:
                    return row['value']
            finally:
                c.close()
            return 'Добро пожаловать в Canno Quest! Введите номер вашего квеста, чтобы начать приключение.'

        def get_homepage_title(self):
            c = repo.connect(); cur = c.cursor()
            try:
                row = cur.execute("SELECT value FROM site_settings WHERE key='homepage_title'").fetchone()
                if row and row['value']:
                    return row['value']
            finally:
                c.close()
            return 'Canno Quest'

        def get_homepage_player_guide(self):
            c = repo.connect(); cur = c.cursor()
            try:
                row = cur.execute("SELECT value FROM site_settings WHERE key='homepage_player_guide'").fetchone()
                if row and row['value']:
                    return row['value']
            finally:
                c.close()
            return 'Введите код квеста, полученный у организатора, и проходите этапы по порядку. Пароли вводите без лишних пробелов.'

        def render_home(self):
            intro = html_lib.escape(self.get_homepage_intro())
            title = html_lib.escape(self.get_homepage_title())
            guide = html_lib.escape(self.get_homepage_player_guide())
            show_logo = self.get_app_setting('homepage_logo_enabled', '1') == '1'
            logo_html = "<img src='/logo.png' alt='Логотип Canno Quest' class='home-logo'>" if show_logo else "<div class='home-logo home-logo-hidden' aria-hidden='true'></div>"
            self.send_html(html(
                "<main class='card home-card screen-home'>"
                "<section class='home-hero v-section'>"
                f"{logo_html}"
                "<div class='home-copy'>"
                f"<h1>{title}</h1>"
                f"<div class='home-intro'><p>{intro}</p></div>"
                f"<div class='home-intro'><h2>Инструкция для игрока</h2><p>{guide}</p></div>"
                "</div>"
                "<div class='home-actions'>"
                "<form class='quest-enter-form' aria-label='Вход в квест по номеру' onsubmit=\"event.preventDefault();const token=(document.getElementById('quest-token').value||'').trim().replace(/^\\/+|\\/+$/g,'');if(token){window.location='/play/'+encodeURIComponent(token);}\">"
                "<div class='quest-enter-row'>"
                "<label class='sr-only' for='quest-token'>Номер квеста</label><input id='quest-token' name='token' placeholder='Номер квеста' maxlength='128' required>"
                "<button class='quest-enter-btn btn'>Войти в квест</button>"
                "</div>"
                "</form>"
                "</div>"
                "</section>"
                "</main>"
            ))

        def save_admin_settings(self, data):
            intro = service.sanitize_text(data.get('homepage_intro', [''])[0], 2000)
            title = service.sanitize_text(data.get('homepage_title', [''])[0], 120) or 'Canno Quest'
            guide = service.sanitize_text(data.get('homepage_player_guide', [''])[0], 2000)
            c = repo.connect(); cur = c.cursor()
            try:
                cur.execute(
                    "INSERT INTO site_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('homepage_intro', intro),
                )
                cur.execute(
                    "INSERT INTO site_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('homepage_title', title),
                )
                cur.execute(
                    "INSERT INTO site_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('homepage_player_guide', guide),
                )
                c.commit()
            finally:
                c.close()
            self.send_response(303)
            self.send_header('Location', '/admin/settings')
            self.end_headers()

        def render_play(self, token):
            c = repo.connect(); cur = c.cursor()
            try:
                p = cur.execute('SELECT * FROM participants WHERE token=?', (token,)).fetchone()
                if not p:
                    quest = cur.execute('SELECT id, access_code FROM quests WHERE access_code=?', (token.upper(),)).fetchone()
                    if quest:
                        participant_token = secrets.token_urlsafe(24)
                        cur.execute(
                            "INSERT INTO participants(quest_id, token, started_at, step_started_at, status) VALUES (?,?,?,?,?)",
                            (quest['id'], participant_token, service.now(), service.now(), 'in_progress'),
                        )
                        c.commit()
                        p = cur.execute('SELECT * FROM participants WHERE token=?', (participant_token,)).fetchone()
                if not p: self.send_html(error_page(404, 'Ссылка недействительна', 'Проверьте URL.'), 404); return
                q = cur.execute('SELECT * FROM quests WHERE id=?', (p['quest_id'],)).fetchone()
                steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (p['quest_id'],)).fetchall()
                if not q['active']: self.send_html(html("<main class='card'><h2>Квест временно закрыт</h2><p>Свяжитесь с организатором и попробуйте позже.</p></main>")); return
                step = next((s for s in steps if s['idx'] == p['current_step']), None)
                locale = service.sanitize_text(parse_qs(urlparse(self.path).query).get('lang', ['ru'])[0], 8)
                english_enabled = self.is_english_enabled()
                if not english_enabled:
                    locale = 'ru'
                prompt = step['prompt_en'] if locale == 'en' and step['prompt_en'] else step['prompt']
                progress = int((p['current_step'] - 1) / len(steps) * 100)
                remaining_html = ''
                if step and step['step_time_limit_sec'] and p['step_started_at']:
                    started_at = datetime.fromisoformat(p['step_started_at'])
                    deadline = started_at + timedelta(seconds=step['step_time_limit_sec'])
                    remaining = (deadline - service.now_dt()).total_seconds()
                    remaining_html = f"<div class='timer-wrap'><p class='muted'>Осталось времени на квест</p><p id='step-timer' class='timer' data-remaining='{int(remaining)}' data-warning='120'>{self.format_seconds(remaining)}</p><p id='step-warning' class='warning hidden'>Мало времени — попробуйте самый очевидный вариант ответа.</p></div>"
                title = q['title_en'] if locale == 'en' and q['title_en'] else q['title']
                self.send_html(html(f"""<main class='card play-card screen-play'><h1>{html_lib.escape(title)}</h1>{remaining_html}<div class='bar stage-progress'><span style='width:{progress}%'></span></div><p class='muted stage-progress-label'><strong>Этап {p['current_step']}</strong> из {len(steps)}</p><p class='prompt'>{html_lib.escape(prompt)}</p><form method='post' class='form-stack'><input name='password' placeholder='Введите пароль' maxlength='128' autocomplete='off' required><button class='btn'>Проверить ответ</button></form><p class='muted'>💡 Совет: ответ без лишних пробелов и символов.</p></main><script>const timer=document.getElementById('step-timer');if(timer){{let remaining=Number(timer.dataset.remaining||0);const warningAt=Number(timer.dataset.warning||120);const warning=document.getElementById('step-warning');const fmt=(n)=>{{const s=Math.max(0,Math.floor(n));const m=String(Math.floor(s/60)).padStart(2,'0');const sec=String(s%60).padStart(2,'0');return m+':'+sec;}};const tick=()=>{{timer.textContent=fmt(remaining);if(remaining<=warningAt&&warning){{warning.classList.remove('hidden');timer.classList.add('timer-danger');}}if(remaining<=0){{clearInterval(iv);}}remaining-=1;}};tick();const iv=setInterval(tick,1000);}}</script>"""))
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
                if not steps or not step:
                    self.send_html(error_page(500, 'Ошибка конфигурации', 'Для квеста не настроены этапы.'), 500); return
                cleaned = service.sanitize_text(password, 128)
                success = int(cleaned == step['password'])
                if step['max_attempts']:
                    failed_count = cur.execute('SELECT COUNT(*) AS c FROM attempts WHERE participant_id=? AND step_idx=? AND success=0', (p['id'], p['current_step'])).fetchone()['c']
                    if failed_count >= step['max_attempts']:
                        cur.execute("UPDATE participants SET status='locked' WHERE id=?", (p['id'],))
                        c.commit()
                        self.send_html(html("<main class='card'><p>Лимит попыток на этапе исчерпан.</p></main>"), 423); return
                cur.execute('INSERT INTO attempts(participant_id,step_idx,entered_password,success,created_at) VALUES (?,?,?,?,?)', (p['id'], p['current_step'], cleaned, success, service.now()))
                if success:
                    auth_store.clear_attempts("step", key)
                    if step['step_time_limit_sec'] and p['step_started_at']:
                        deadline = datetime.fromisoformat(p['step_started_at']) + timedelta(seconds=step['step_time_limit_sec'])
                        if service.now_dt() > deadline:
                            self.send_html(html(f"<main class='card'><h2>Время этапа вышло</h2><p>Ответ верный, но лимит времени уже истёк. Перезапустите этап и попробуйте снова.</p><a href='/play/{token}'>Вернуться к этапу</a></main>"), 409); return
                    if p['current_step'] >= len(steps):
                        cur.execute("UPDATE participants SET completed=1, status='completed' WHERE id=?", (p['id'],))
                        self.audit('player', 'participant.completion', target=f'participant:{p["id"]}', metadata={'participant_id': p['id'], 'token': token, 'quest_id': p['quest_id']})
                    else:
                        next_idx = step['next_on_success_idx'] or (p['current_step'] + 1)
                        cur.execute("UPDATE participants SET current_step=?, step_started_at=?, status='in_progress' WHERE id=?", (next_idx, service.now(), p['id']))
                    c.commit(); self.send_response(303); self.send_header('Location', f'/play/{token}'); self.end_headers(); return
                c.commit()
                self._record_attempt("step", key)
                if step['penalty_sec']:
                    cur.execute("UPDATE participants SET step_started_at=? WHERE id=?", ((service.now_dt() - timedelta(seconds=step['penalty_sec'])).isoformat(), p['id']))
                    c.commit()
                hint = self.player_hint(p['current_step'])
                self.send_html(html(f"<main class='card'><h2>Пока не подошло</h2><p>Неверный пароль. Проверьте раскладку клавиатуры и попробуйте ещё раз.</p><p class='hint'>Подсказка: {html_lib.escape(hint)}</p><a href='/play/{token}'>Вернуться к этапу</a></main>"))
            finally:
                c.close()

        def render_admin(self):
            self.send_html(html("<main class='card admin-hub-card screen-admin'><h1>⚙️ Админка</h1><div class='nav-links'><a class='btn btn-ghost' href='/admin/quest/new'>Редактор квестов</a><a class='btn btn-ghost' href='/admin/settings'>Технические настройки</a><a class='btn btn-ghost' href='/admin/logout'>Выйти</a></div></main>"))

        def render_admin_settings(self):
            intro = html_lib.escape(self.get_homepage_intro())
            title = html_lib.escape(self.get_homepage_title())
            guide = html_lib.escape(self.get_homepage_player_guide())
            logo_path = html_lib.escape(self.get_app_setting('homepage_logo_path', 'static/images/logo1.png'))
            logo_enabled_checked = "checked" if self.get_app_setting('homepage_logo_enabled', '1') == '1' else ''
            editors_html = self.render_editor_accounts()
            self.send_html(html(f"<main class='card admin-settings-card screen-admin-settings'><h1>🛠️ Техническая админка</h1><nav class='settings-tabs' data-tabs><button class='btn btn-ghost tab-btn is-active' type='button' data-tab-target='tab-general'>Общие настройки</button><button class='btn btn-ghost tab-btn' type='button' data-tab-target='tab-editors'>Редакторы</button><button class='btn btn-ghost tab-btn' type='button' data-tab-target='tab-ui'>Интерфейс и текст</button></nav><section id='tab-general' class='tab-panel is-active'><h2>Общие настройки</h2><div class='nav-links'><a class='btn btn-ghost' href='/admin/quests/export.json'>Экспорт квестов (JSON)</a><a class='btn btn-ghost' href='/admin/audit'>Журнал аудита</a><a class='btn btn-ghost' href='/admin/runs/archive'>Архивировать завершенные запуски</a></div><h2>Импорт JSON</h2><form method='post' action='/admin/quests/import' class='admin-form'><textarea name='payload' rows='8' placeholder='{{\"quests\": [ ... ]}}'></textarea><button class='btn-secondary btn-outline'>Импортировать JSON</button></form></section><section id='tab-editors' class='tab-panel'><h2>Список редакторов</h2>{editors_html}</section><section id='tab-ui' class='tab-panel'><h2>Текст на главной</h2><form method='post' action='/admin/settings/save' class='admin-form'><label for='homepage-title'>Основной заголовок</label><input id='homepage-title' name='homepage_title' maxlength='120' value='{title}' placeholder='Canno Quest' required><label for='homepage-intro'>Описание приложения</label><textarea id='homepage-intro' name='homepage_intro' rows='4' maxlength='2000'>{intro}</textarea><label for='homepage-guide'>Инструкция для игрока</label><textarea id='homepage-guide' name='homepage_player_guide' rows='4' maxlength='2000'>{guide}</textarea><h2>Логотип на главной</h2><label for='homepage-logo-path'>Путь к логотипу (внутри проекта)</label><input id='homepage-logo-path' name='homepage_logo_path' maxlength='512' value='{logo_path}' placeholder='static/images/logo1.png'><label><input type='checkbox' name='homepage_logo_enabled' {logo_enabled_checked}>Показывать логотип на главной</label><button class='btn'>Сохранить текст главной</button></form></section></main><script>(function(){{const tabs=document.querySelectorAll('.tab-btn');const panels=document.querySelectorAll('.tab-panel');if(!tabs.length||!panels.length)return;tabs.forEach((btn)=>btn.addEventListener('click',()=>{{tabs.forEach((b)=>b.classList.toggle('is-active',b===btn));panels.forEach((panel)=>panel.classList.toggle('is-active',panel.id===btn.dataset.tabTarget));}}));}})();</script>"))

        def render_editor_accounts(self):
            c = repo.connect()
            try:
                rows = c.execute('SELECT id, username, is_active FROM editor_accounts ORDER BY username').fetchall()
            finally:
                c.close()
            items = ''.join([f"<tr><td>{r['id']}</td><td>{html_lib.escape(r['username'])}</td><td>{'Активен' if r['is_active'] else 'Отключен'}</td></tr>" for r in rows])
            return f"<div class='table-wrap'><table><tr><th>ID</th><th>Логин</th><th>Статус</th></tr>{items}</table></div><form method='post' action='/admin/editors/save' class='admin-form'><label>Логин редактора</label><input name='editor_username' maxlength='64' required><label>Пароль редактора</label><input type='password' name='editor_password' maxlength='256' required><button class='btn'>Создать / обновить</button></form>"

        def export_participants_csv(self):
            self.send_response(200); self.end_headers()

        def render_metrics(self, query):
            self.send_html(html("<main class='card metrics-card screen-metrics'><h1>Метрики</h1></main>"))


        def render_quest_form(self, quest_id=None):
            self.audit('admin', 'admin.quest.form.view', target=f'quest:{quest_id or "new"}', metadata={'quest_id': quest_id})
            c = repo.connect(); cur = c.cursor()
            quest_columns = {row['name'] for row in cur.execute("PRAGMA table_info(quests)").fetchall()}
            has_title_en = 'title_en' in quest_columns
            has_access_code = 'access_code' in quest_columns
            has_quest_time_limit = 'quest_time_limit_sec' in quest_columns
            if has_access_code:
                uncoded = cur.execute('SELECT id FROM quests WHERE access_code IS NULL OR access_code=""').fetchall()
                for qrow in uncoded:
                    cur.execute('UPDATE quests SET access_code=? WHERE id=?', (self.generate_quest_code(cur), qrow['id']))
                if uncoded:
                    c.commit()
            title_en_select = 'title_en' if has_title_en else "'' AS title_en"
            access_code_select = 'access_code' if has_access_code else "'' AS access_code"
            quest_time_limit_select = 'quest_time_limit_sec' if has_quest_time_limit else '0 AS quest_time_limit_sec'
            quests = cur.execute(f'SELECT id, title, {title_en_select}, final_location, active, {quest_time_limit_select}, {access_code_select} FROM quests ORDER BY id DESC').fetchall()
            show_english = self.is_english_enabled()
            selected = None
            steps = []
            if quest_id:
                selected = cur.execute(f'SELECT id, title, {title_en_select}, final_location, active, {quest_time_limit_select}, {access_code_select} FROM quests WHERE id=?', (quest_id,)).fetchone()
                steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (quest_id,)).fetchall()
            c.close()

            def esc(value):
                return html_lib.escape(str(value or ''))

            selected_id = selected['id'] if selected else ''
            title = esc(selected['title']) if selected else ''
            title_en = esc(selected['title_en']) if selected else ''
            final_location = esc(selected['final_location']) if selected else ''

            row_items = []
            for q in quests:
                status_badge = '<span class="status-badge status-active">Активен</span>' if q['active'] else '<span class="status-badge status-paused">Пауза</span>'
                row_items.append(
                    f"<tr data-title='{esc(q['title']).lower()}' data-status='{'active' if q['active'] else 'paused'}' data-limit='{q['quest_time_limit_sec'] or 0}' data-id='{q['id']}'>"
                    f"<td>{q['id']}</td><td><a class='quest-title-link' href='/admin/quest/edit?id={q['id']}'><strong>{esc(q['title'])}</strong></a><button class='icon-action btn btn-ghost inline-copy-link copy-link-btn' type='button' title='Скопировать URL квеста' aria-label='Скопировать ссылку квеста #{q['id']}' data-path='/play/{esc(q['access_code'])}'><span aria-hidden='true'>🔗</span><span class='sr-only'>Скопировать ссылку квеста #{q['id']}</span></button><br><small class='muted'>Код: {esc(q['access_code'])} · {esc(q['final_location']) or '—'}</small></td><td>{status_badge}</td><td>{self.format_limit_label(q['quest_time_limit_sec'])}</td>"
                    f"<td><div class='action-icon-group'>"
                                        f"<a class='icon-action btn btn-ghost' title='Запустить тест' aria-label='Запустить тест квеста #{q['id']}' href='/play/{esc(q['access_code'])}'><span aria-hidden='true'>🧪</span><span class='sr-only'>Запустить тест квеста #{q['id']}</span></a>"
                                        f"<form method='post' action='/admin/quest/toggle'><input type='hidden' name='id' value='{q['id']}'><button class='icon-action btn btn-ghost' title='{'Отключить' if q['active'] else 'Включить'}' aria-label='{'Отключить' if q['active'] else 'Включить'} квест #{q['id']}'><span aria-hidden='true'>{'⏸' if q['active'] else '🟢'}</span><span class='sr-only'>{'Отключить' if q['active'] else 'Включить'} квест #{q['id']}</span></button></form>"
                    f"</div></td></tr>"
                )

            rows = ''.join(row_items)
            edit_form = ''
            steps_block = ''
            if selected_id:
                title_en_input = f"<input name='title_en' placeholder='Название (EN)' maxlength='256' value='{title_en}'>" if show_english else ''
                step_rows = ''.join([f"<div class='step-row'><input type='hidden' name='step_id' value='{st['id']}'><input class='step-idx' name='step_idx' type='number' min='1' value='{st['idx']}' readonly required><textarea name='step_prompt' rows='2' placeholder='Загадка' required>{esc(st['prompt'])}</textarea><input name='step_password' placeholder='Пароль' value='{esc(st['password'])}' required><button type='button' class='btn-secondary btn-outline step-remove-btn'>Удалить</button></div>" for st in steps])
                edit_form = f"<form method='post' action='/admin/quest/save' class='admin-form compact-form'><input type='hidden' name='id' value='{selected_id}'><input name='title' placeholder='Название' maxlength='256' required value='{title}'>{title_en_input}<input name='final_location' placeholder='Финальная локация' maxlength='512' value='{final_location}'><label for='quest-time-amount'>Лимит на весь квест</label><div class='inline-time'><input id='quest-time-amount' class='time-input' name='quest_time_limit_amount' type='number' min='0' placeholder='30'><select name='quest_time_limit_unit' class='time-unit'><option value='minutes'>минуты</option><option value='hours'>часы</option></select></div><p class='muted'>Код доступа: <strong>{esc(selected['access_code'])}</strong></p><section class='steps-compact'><h3>Этапы</h3><div id='steps-container'>{step_rows}</div><div class='step-actions'><button type='button' id='add-step-btn' class='btn-secondary btn-outline'>+ Этап</button></div></section><div class='form-actions'><button class='btn'>Сохранить квест</button><a class='btn btn-outline' href='/admin/quest/edit?id={selected_id}'>Отменить изменения</a></div></form>"

            page = f"""
<main class='card admin-card screen-quest-form'>
  <h1>🧩 Управление квестами</h1>

  {"<section class='quest-list-panel'>" if not selected_id else ""}
    <div class='quest-list-toolbar'>
      <input id='quest-filter' type='search' placeholder='Фильтр по названию...'>
      <select id='quest-status-filter'>
        <option value='all'>Все статусы</option>
        <option value='active'>Активные</option>
        <option value='paused'>На паузе</option>
      </select>
      <select id='quest-sort'>
        <option value='id_desc'>Сначала новые</option>
        <option value='id_asc'>Сначала старые</option>
        <option value='title_asc'>По названию А-Я</option>
        <option value='title_desc'>По названию Я-А</option>
      </select>
    </div>
    <div class='table-wrap'><table id='quest-table'><tr><th>ID</th><th>Квест</th><th>Статус</th><th>Лимит</th><th>Действия</th></tr>{rows}</table></div>
  {"</section>" if not selected_id else ""}

  <section class='quest-edit-panel'>
    <h2>{'Редактирование квеста #' + str(selected_id) if selected_id else ''}</h2>
    {edit_form if selected_id else ""}
  </section>

  {steps_block}
</main>
<script>
(function(){{
  const tabs=document.querySelectorAll('.tab-btn');const panels=document.querySelectorAll('.tab-panel');if(tabs.length&&panels.length){{tabs.forEach(btn=>btn.addEventListener('click',()=>{{tabs.forEach(b=>b.classList.toggle('is-active',b===btn));panels.forEach(p=>p.classList.toggle('is-active',p.id===btn.dataset.tabTarget));}}));}}
  const table=document.getElementById('quest-table'); if(!table) return;
  const filter=document.getElementById('quest-filter');
  const status=document.getElementById('quest-status-filter');
  const sort=document.getElementById('quest-sort');
  const tbodyRows=Array.from(table.querySelectorAll('tr')).slice(1);
  function apply(){{
    const f=(filter.value||'').toLowerCase();
    const s=status.value;
    const rows=[...tbodyRows].filter(r=>r.dataset.title.includes(f)&&(s==='all'||r.dataset.status===s));
    rows.sort((a,b)=>{{if(sort.value==='id_asc')return Number(a.dataset.id)-Number(b.dataset.id);if(sort.value==='title_asc')return a.dataset.title.localeCompare(b.dataset.title,'ru');if(sort.value==='title_desc')return b.dataset.title.localeCompare(a.dataset.title,'ru');return Number(b.dataset.id)-Number(a.dataset.id)}});
    tbodyRows.forEach(r=>r.remove()); rows.forEach(r=>table.appendChild(r));
  }}
  [filter,status,sort].forEach(el=>el.addEventListener('input',apply)); apply();
  document.querySelectorAll('.copy-link-btn').forEach(btn=>btn.addEventListener('click',async()=>{{const url=window.location.origin+btn.dataset.path;try{{await navigator.clipboard.writeText(url);const icon=btn.querySelector('span[aria-hidden=true]');if(icon)icon.textContent='✅';setTimeout(()=>{{if(icon)icon.textContent='🔗';}},1000);}}catch(e){{prompt('Скопируйте URL:',url);}}}}));
  const stepsContainer=document.getElementById('steps-container');
  const addBtn=document.getElementById('add-step-btn');
  if(stepsContainer&&addBtn){{
    addBtn.addEventListener('click',()=>{{
      const row=document.createElement('div');
      row.className='step-row';
      row.innerHTML=\"<input type='hidden' name='step_id' value=''><input class='step-idx' name='step_idx' type='number' min='1' readonly required><textarea name='step_prompt' rows='2' placeholder='Загадка' required></textarea><input name='step_password' placeholder='Пароль' required><button type='button' class='btn-secondary btn-outline step-remove-btn'>Удалить</button>\";
      stepsContainer.appendChild(row);
      renumberSteps();
    }});
    const renumberSteps=()=>Array.from(stepsContainer.querySelectorAll('.step-idx')).forEach((input,idx)=>input.value=idx+1);renumberSteps();
    stepsContainer.addEventListener('click',(e)=>{{const target=e.target; if(target&&target.classList.contains('step-remove-btn')){{target.closest('.step-row')?.remove();renumberSteps();}}}});
  }}
}})();
</script>
"""
            self.send_html(html(page))


        def save_admin_settings(self, data):
            intro = service.sanitize_text(data.get('homepage_intro', [''])[0], 2000)
            title = service.sanitize_text(data.get('homepage_title', [''])[0], 120) or 'Canno Quest'
            enable_english = '1' if data.get('enable_english_content', [''])[-1] in ('on', '1', 'true') else '0'
            logo_path = service.sanitize_text(data.get('homepage_logo_path', ['static/images/logo1.png'])[0], 512) or 'static/images/logo1.png'
            logo_enabled = '1' if data.get('homepage_logo_enabled', [''])[-1] in ('on', '1', 'true') else '0'
            c = repo.connect(); cur = c.cursor()
            try:
                cur.execute(
                    "INSERT INTO site_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('homepage_intro', intro),
                )
                cur.execute(
                    "INSERT INTO site_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('homepage_title', title),
                )
                cur.execute(
                    "INSERT INTO app_settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('enable_english_content', enable_english),
                )
                cur.execute(
                    "INSERT INTO app_settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('homepage_logo_path', logo_path),
                )
                cur.execute(
                    "INSERT INTO app_settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('homepage_logo_enabled', logo_enabled),
                )
                c.commit()
            finally:
                c.close()
            self.audit('admin', 'admin.settings.updated', metadata={'enable_english_content': enable_english, 'homepage_title': title})
            self.send_response(303); self.send_header('Location', '/admin/settings'); self.end_headers()

        def save_editor_account(self, data):
            username = service.sanitize_text(data.get('editor_username', [''])[0], 64)
            password = service.sanitize_text(data.get('editor_password', [''])[0], 256)
            if not username or not password:
                self.send_html(error_page(400, 'Некорректные данные', 'Логин и пароль редактора обязательны.'), 400); return
            password_hash = service.hash_password(password)
            c = repo.connect(); cur = c.cursor()
            try:
                cur.execute(
                    "INSERT INTO editor_accounts(username, password_hash, is_active) VALUES(?,?,1) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, is_active=1",
                    (username, password_hash),
                )
                c.commit()
            finally:
                c.close()
            self.audit('admin', 'admin.editor_account.saved', target=username, metadata={'username': username})
            self.send_response(303); self.send_header('Location', '/admin/settings#tab-editors'); self.end_headers()

        def save_quest_settings(self, data):
            quest_id = service.parse_int(data.get('id', [''])[0], minimum=1)
            title = service.sanitize_text(data.get('title', [''])[0], 256)
            title_en = service.sanitize_text(data.get('title_en', [''])[0], 256) if self.is_english_enabled() else ''
            final_location = service.sanitize_text(data.get('final_location', [''])[0], 512)
            quest_time_limit_sec = self.parse_duration_seconds(
                data.get('quest_time_limit_amount', [''])[0],
                data.get('quest_time_limit_unit', ['minutes'])[0],
                data.get('quest_time_limit_sec', [''])[0],
            )
            if not title:
                self.send_html(error_page(400, 'Некорректные данные', 'Название квеста обязательно'), 400); return
            c = repo.connect(); cur = c.cursor()
            if quest_id:
                row = cur.execute('SELECT active FROM quests WHERE id=?', (quest_id,)).fetchone()
                active = row['active'] if row else 0
                cur.execute('UPDATE quests SET title=?, title_en=?, final_location=?, active=?, quest_time_limit_sec=? WHERE id=?', (title, title_en, final_location, active, quest_time_limit_sec, quest_id))
                action = 'admin.quest.updated'
            else:
                active = 0
                access_code = self.generate_quest_code(cur)
                cur.execute('INSERT INTO quests(title,title_en,final_location,active,quest_time_limit_sec,access_code) VALUES (?,?,?,?,?,?)', (title, title_en, final_location, active, quest_time_limit_sec, access_code))
                quest_id = cur.lastrowid
                action = 'admin.quest.created'
            step_ids = data.get('step_id', [])
            step_indexes = data.get('step_idx', [])
            step_prompts = data.get('step_prompt', [])
            step_passwords = data.get('step_password', [])
            incoming_steps = []
            for idx, prompt, password, step_id_raw in zip(step_indexes, step_prompts, step_passwords, step_ids):
                parsed_idx = service.parse_int(idx, minimum=1)
                clean_prompt = service.sanitize_text(prompt, 2000)
                clean_password = service.sanitize_text(password, 128)
                parsed_step_id = service.parse_int(step_id_raw, minimum=1)
                if parsed_idx and clean_prompt and clean_password:
                    incoming_steps.append({'id': parsed_step_id, 'idx': parsed_idx, 'prompt': clean_prompt, 'password': clean_password})
            if quest_id and incoming_steps:
                existing_ids = {row['id'] for row in cur.execute('SELECT id FROM steps WHERE quest_id=?', (quest_id,)).fetchall()}
                keep_ids = set()
                for st in incoming_steps:
                    if st['id'] and st['id'] in existing_ids:
                        cur.execute('UPDATE steps SET idx=?, prompt=?, password=? WHERE id=? AND quest_id=?', (st['idx'], st['prompt'], st['password'], st['id'], quest_id))
                        keep_ids.add(st['id'])
                    else:
                        cur.execute('INSERT INTO steps(quest_id,idx,prompt,password) VALUES (?,?,?,?)', (quest_id, st['idx'], st['prompt'], st['password']))
                        keep_ids.add(cur.lastrowid)
                for existing_id in existing_ids - keep_ids:
                    cur.execute('DELETE FROM steps WHERE id=? AND quest_id=?', (existing_id, quest_id))
            c.commit(); c.close()
            self.audit('admin', action, target=f'quest:{quest_id}', metadata={'quest_id': quest_id})
            self.send_response(303); self.send_header('Location', '/admin/quest/new'); self.end_headers()

        def toggle_quest(self, data):
            quest_id = service.parse_int(data.get('id', [''])[0], minimum=1)
            if not quest_id:
                self.send_html(error_page(400, 'Некорректные данные', 'id квеста обязателен'), 400); return
            c = repo.connect(); cur = c.cursor()
            row = cur.execute('SELECT active FROM quests WHERE id=?', (quest_id,)).fetchone()
            if not row:
                c.close(); self.send_html(error_page(404, 'Не найдено', 'Квест не найден'), 404); return
            new_active = 0 if row['active'] else 1
            cur.execute('UPDATE quests SET active=? WHERE id=?', (new_active, quest_id))
            c.commit(); c.close()
            self.audit('admin', 'admin.quest.toggled', target=f'quest:{quest_id}', metadata={'quest_id': quest_id, 'active': new_active})
            self.send_response(303); self.send_header('Location', '/admin/quest/new'); self.end_headers()

        def save_quest_step(self, data):
            quest_id = service.parse_int(data.get('quest_id', [''])[0], minimum=1)
            step_id = service.parse_int(data.get('step_id', [''])[0], minimum=1)
            idx = service.parse_int(data.get('idx', [''])[0], minimum=1)
            prompt = service.sanitize_text(data.get('prompt', [''])[0], 2000)
            password = service.sanitize_text(data.get('password', [''])[0], 128)
            step_time_limit_sec = self.parse_duration_seconds(
                data.get('step_time_limit_amount', [''])[0],
                data.get('step_time_limit_unit', ['minutes'])[0],
                data.get('step_time_limit_sec', [''])[0],
            )
            if not quest_id or not idx or not prompt or not password:
                self.send_html(error_page(400, 'Некорректные данные', 'Заполните обязательные поля этапа'), 400); return
            c = repo.connect(); cur = c.cursor()
            if step_id:
                cur.execute('UPDATE steps SET idx=?, prompt=?, password=?, step_time_limit_sec=? WHERE id=? AND quest_id=?', (idx, prompt, password, step_time_limit_sec, step_id, quest_id))
            else:
                cur.execute('INSERT INTO steps(quest_id,idx,prompt,password,step_time_limit_sec) VALUES (?,?,?,?,?)', (quest_id, idx, prompt, password, step_time_limit_sec))
            c.commit(); c.close()
            self.audit('editor', 'editor.step.saved', target=f'quest:{quest_id}', metadata={'quest_id': quest_id, 'step_id': step_id, 'idx': idx})
            self.send_response(303); self.send_header('Location', '/admin/quest/new'); self.end_headers()

        def import_quest_json(self, data):
            payload = data.get('payload', ['{}'])[0]
            body = json.loads(payload)
            c = repo.connect(); cur = c.cursor()
            for quest in body.get('quests', []):
                cur.execute('INSERT INTO quests(title,title_en,final_location,active,quest_time_limit_sec) VALUES (?,?,?,?,?)', (
                    service.sanitize_text(quest.get('title', ''), 256),
                    service.sanitize_text(quest.get('title_en', ''), 256),
                    service.sanitize_text(quest.get('final_location', ''), 512),
                    int(quest.get('active', 1)),
                    quest.get('quest_time_limit_sec'),
                ))
                quest_id = cur.lastrowid
                version = cur.execute('SELECT COALESCE(MAX(version),0)+1 AS v FROM quest_versions WHERE quest_id=?', (quest_id,)).fetchone()['v']
                cur.execute('INSERT INTO quest_versions(quest_id,version,payload_json,created_at) VALUES (?,?,?,?)', (quest_id, version, json.dumps(quest, ensure_ascii=False), service.now()))
                for step in quest.get('steps', []):
                    cur.execute('INSERT INTO steps(quest_id,idx,prompt,prompt_en,password,step_time_limit_sec,next_on_success_idx,max_attempts,penalty_sec) VALUES (?,?,?,?,?,?,?,?,?)', (
                        quest_id, step.get('idx'), step.get('prompt'), step.get('prompt_en', ''), step.get('password'), step.get('step_time_limit_sec'),
                        step.get('next_on_success_idx'), step.get('max_attempts'), step.get('penalty_sec'),
                    ))
            c.commit(); c.close()
            self.send_response(303); self.send_header('Location', '/admin/quest/new'); self.end_headers()

        def archive_completed_runs(self):
            c = repo.connect(); cur = c.cursor()
            rows = cur.execute("SELECT * FROM participants WHERE completed=1").fetchall()
            for row in rows:
                attempts = [dict(a) for a in cur.execute('SELECT * FROM attempts WHERE participant_id=? ORDER BY id', (row['id'],)).fetchall()]
                cur.execute('INSERT INTO quest_run_archive(participant_id,quest_id,token,status,completed,archived_at,payload_json) VALUES (?,?,?,?,?,?,?)', (
                    row['id'], row['quest_id'], row['token'], row['status'], row['completed'], service.now(), json.dumps({'participant': dict(row), 'attempts': attempts}, ensure_ascii=False),
                ))
                cur.execute('DELETE FROM attempts WHERE participant_id=?', (row['id'],))
                cur.execute('DELETE FROM participants WHERE id=?', (row['id'],))
            c.commit(); c.close()
            self.send_html(html(f"<main class='card'><h2>Архивировано запусков: {len(rows)}</h2></main>"))

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
            self.send_html(html(f"<main class='card audit-card screen-audit'><h1>Аудит</h1><form class='audit-filters form-stack'><input name='from' placeholder='from ISO' value='{html_lib.escape(date_from)}'><input name='to' placeholder='to ISO' value='{html_lib.escape(date_to)}'><input name='action' placeholder='action' value='{html_lib.escape(action)}'><input name='quest_id' placeholder='quest_id' value='{quest_id or ''}'><button class='btn'>Фильтр</button></form><p><a href='{html_lib.escape(export_link)}'>Экспорт CSV</a></p><table><tr><th>Время</th><th>Actor</th><th>Action</th><th>Target</th><th>Metadata</th><th>IP</th></tr>{items}</table></main>"))

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
