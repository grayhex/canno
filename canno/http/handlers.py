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
            self.send_header('Location', '/editor/login')
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

        def do_GET(self):
            try:
                p = urlparse(self.path)
                if p.path == '/':
                    self.render_home(); return
                if p.path == '/static.css':
                    css = (BASE_DIR / 'static.css').read_text(encoding='utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/css')
                    self.end_headers()
                    self.wfile.write(css.encode())
                    return
                if p.path == '/logo.png':
                    logo = BASE_DIR / 'logo1.png'
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
                    self.render_login(); return
                if p.path == '/editor/login':
                    self.render_login('editor'); return
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
                    self.render_quest_form(); return
                if p.path == '/admin/quest/edit':
                    if not self.require_editor(): return
                    quest_id = service.parse_int(parse_qs(p.query).get('id', [''])[0], minimum=1)
                    if not quest_id:
                        self.send_html(error_page(400, 'Некорректные данные', 'id квеста обязателен'), 400); return
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
            except Exception:
                logger.exception('Unhandled GET error')
                self.send_html(error_page(500, 'Ошибка сервера', 'Попробуйте снова позже.'), 500)

        def do_POST(self):
            p = urlparse(self.path)
            length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(length).decode(errors='ignore')
            data = parse_qs(raw_body)
            if p.path == '/admin/login':
                return self.handle_login(data, 'admin')
            if p.path == '/editor/login':
                return self.handle_login(data, 'editor')
            if p.path == '/admin/quests/import':
                if not self.require_admin(): return
                return self.import_quest_json(data)
            if p.path == '/admin/settings/save':
                if not self.require_admin(): return
                return self.save_admin_settings(data)
            if p.path == '/admin/quest/save':
                if not self.require_editor(): return
                return self.save_quest_settings(data)
            if p.path == '/admin/settings/save':
                if not self.require_admin(): return
                return self.save_admin_settings(data)
            if p.path == '/admin/quest/toggle':
                if not self.require_editor(): return
                return self.toggle_quest(data)
            if p.path == '/admin/step/save':
                if not self.require_editor(): return
                return self.save_quest_step(data)
            if p.path.startswith('/play/'):
                return self.submit_password(service.sanitize_text(p.path.split('/play/')[1], 128), data.get('password', [''])[0])
            self.send_json({'error': 'not found'}, 404)

        def render_login(self, role='admin', error=''):
            err = f"<p class='error'>{html_lib.escape(error)}</p>" if error else ''
            title = 'админку' if role == 'admin' else 'панель редактора'
            self.send_html(html(f"<main class='card'><h1>🔐 Вход в {title}</h1>{err}<form method='post'><input name='username' placeholder='Логин' maxlength='64' required><input type='password' name='password' maxlength='256' placeholder='Пароль' required><button>Войти</button></form></main>"))

        def handle_login(self, data, role='admin'):
            ip = self.client_ip()
            if self._blocked("login", ip, config.MAX_LOGIN_ATTEMPTS, config.LOGIN_WINDOW_SECONDS):
                self.render_login(role, 'Слишком много попыток. Повторите позже.'); return
            username = service.sanitize_text(data.get('username', [''])[0], 64)
            password = service.sanitize_text(data.get('password', [''])[0], 256)
            expected_user = config.ADMIN_USER if role == 'admin' else config.EDITOR_USER
            expected_hash = admin_password_hash_value if role == 'admin' else service.resolve_password_hash(config.EDITOR_PASSWORD_HASH, config.EDITOR_PASSWORD)
            if username == expected_user and service.verify_password(password, expected_hash):
                sid = secrets.token_urlsafe(32)
                auth_store.set(sid, service.now_dt() + timedelta(hours=8), role=role)
                self.audit(role, f'{role}.login.success', target=username, metadata={'session_id': sid}, ip=ip)
                self.send_response(303)
                self.send_header('Location', '/admin' if role == 'admin' else '/admin/quest/new')
                self.send_header('Set-Cookie', f'{config.SESSION_COOKIE}={sid}; HttpOnly; Path=/; SameSite=Lax')
                self.end_headers()
                return
            self._record_attempt("login", ip)
            self.audit(role, f'{role}.login.failed', target=username, metadata={'reason': 'invalid_credentials'}, ip=ip)
            self.render_login(role, 'Неверный логин или пароль.')

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

        def get_homepage_intro(self):
            c = repo.connect(); cur = c.cursor()
            try:
                row = cur.execute("SELECT value FROM site_settings WHERE key='homepage_intro'").fetchone()
                if row and row['value']:
                    return row['value']
            finally:
                c.close()
            return 'Добро пожаловать в Canno Quest! Введите номер вашего квеста, чтобы начать приключение.'

        def render_home(self):
            intro = html_lib.escape(self.get_homepage_intro())
            self.send_html(html(
                "<main class='card home-card'>"
                "<img src='/logo.png' alt='Логотип Canno Quest' class='home-logo'>"
                "<h1>Canno Quest</h1>"
                "<div class='home-login-links'>"
                "<a href='/admin/login' class='home-login-btn'>🛡️ Вход администратора</a>"
                "<a href='/editor/login' class='home-login-btn'>✍️ Вход редактора</a>"
                "</div>"
                f"<div class='home-intro'><p>{intro}</p></div>"
                "<form class='quest-enter-form' onsubmit=\"event.preventDefault();const token=(document.getElementById('quest-token').value||'').trim().replace(/^\\/+|\\/+$/g,'');if(token){window.location='/play/'+encodeURIComponent(token);}\">"
                "<div class='quest-enter-row'>"
                "<input id='quest-token' name='token' placeholder='Номер квеста' maxlength='128' required>"
                "<button class='quest-enter-btn'>Войти</button>"
                "</div>"
                "</form>"
                "</main>"
            ))

        def save_admin_settings(self, data):
            intro = service.sanitize_text(data.get('homepage_intro', [''])[0], 2000)
            c = repo.connect(); cur = c.cursor()
            try:
                cur.execute(
                    "INSERT INTO site_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ('homepage_intro', intro),
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
                    remaining_html = f"<div class='timer-wrap'><p class='muted'>Осталось времени на этап</p><p id='step-timer' class='timer' data-remaining='{int(remaining)}' data-warning='120'>{self.format_seconds(remaining)}</p><p id='step-warning' class='warning hidden'>Мало времени — попробуйте самый очевидный вариант ответа.</p></div>"
                title = q['title_en'] if locale == 'en' and q['title_en'] else q['title']
                self.send_html(html(f"""<main class='card'><h1>{html_lib.escape(title)}</h1><div class='bar'><span style='width:{progress}%'></span></div><p class='muted'>Этап {p['current_step']} из {len(steps)}</p>{remaining_html}<p class='prompt'>{html_lib.escape(prompt)}</p><form method='post'><input name='password' placeholder='Введите пароль' maxlength='128' autocomplete='off' required><button>Проверить ответ</button></form><p class='muted'>💡 Совет: ответ без лишних пробелов и символов.</p></main><script>const timer=document.getElementById('step-timer');if(timer){{let remaining=Number(timer.dataset.remaining||0);const warningAt=Number(timer.dataset.warning||120);const warning=document.getElementById('step-warning');const fmt=(n)=>{{const s=Math.max(0,Math.floor(n));const m=String(Math.floor(s/60)).padStart(2,'0');const sec=String(s%60).padStart(2,'0');return m+':'+sec;}};const tick=()=>{{timer.textContent=fmt(remaining);if(remaining<=warningAt&&warning){{warning.classList.remove('hidden');timer.classList.add('timer-danger');}}if(remaining<=0){{clearInterval(iv);}}remaining-=1;}};tick();const iv=setInterval(tick,1000);}}</script>"""))
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
            self.send_html(html("<main class='card'><h1>⚙️ Админка</h1><div class='nav-links'><a href='/admin/quest/new'>Редактор квестов</a><a href='/admin/settings'>Технические настройки</a><a href='/admin/logout'>Выйти</a></div></main>"))

        def render_admin_settings(self):
            intro = html_lib.escape(self.get_homepage_intro())
            self.send_html(html(f"<main class='card'><h1>🛠️ Технические настройки</h1><div class='nav-links'><a href='/admin/quests/export.json'>Экспорт квестов (JSON)</a><a href='/admin/audit'>Журнал аудита</a><a href='/admin/runs/archive'>Архивировать завершенные запуски</a><a href='/admin'>← Назад</a></div><h2>Текст на главной</h2><form method='post' action='/admin/settings/save' class='admin-form'><textarea name='homepage_intro' rows='4' maxlength='2000'>{intro}</textarea><button>Сохранить текст главной</button></form><h2>Импорт JSON</h2><form method='post' action='/admin/quests/import' class='admin-form'><textarea name='payload' rows='8' placeholder='{{\"quests\": [ ... ]}}'></textarea><button class='btn-secondary'>Импортировать JSON</button></form></main>"))

        def export_participants_csv(self):
            self.send_response(200); self.end_headers()

        def render_metrics(self, query):
            self.send_html(html("<main class='card'><h1>Метрики</h1></main>"))

        def render_quest_form(self, quest_id=None):
            self.audit('admin', 'admin.quest.form.view', target=f'quest:{quest_id or "new"}', metadata={'quest_id': quest_id})
            c = repo.connect(); cur = c.cursor()
            quests = cur.execute('SELECT id, title, title_en, final_location, active, quest_time_limit_sec FROM quests ORDER BY id DESC').fetchall()
            show_english = self.is_english_enabled()
            selected = None
            steps = []
            if quest_id:
                selected = cur.execute('SELECT id, title, title_en, final_location, active, quest_time_limit_sec FROM quests WHERE id=?', (quest_id,)).fetchone()
                steps = cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx', (quest_id,)).fetchall()
            c.close()

            def esc(value):
                return html_lib.escape(str(value or ''))

            selected_id = selected['id'] if selected else ''
            title = esc(selected['title']) if selected else ''
            title_en = esc(selected['title_en']) if selected else ''
            final_location = esc(selected['final_location']) if selected else ''
            time_limit = selected['quest_time_limit_sec'] if selected and selected['quest_time_limit_sec'] else ''
            checked = 'checked' if selected and selected['active'] else ''

            row_items = []
            for q in quests:
                toggle_label = 'Отключить' if q['active'] else 'Включить'
                status = '✅' if q['active'] else '⏸️'
                row_items.append(
                    f"<tr><td>{q['id']}</td><td>{esc(q['title'])}<br><small class='muted'>share: /play/{q['id']}</small></td><td>{status}</td><td>{q['quest_time_limit_sec'] or '-'} сек</td>"
                    f"<td><div class='action-group'><a class='link-btn' href='/admin/quest/edit?id={q['id']}'>Открыть</a>"
                    f"<form method='post' action='/admin/quest/toggle'><input type='hidden' name='id' value='{q['id']}'><button class='btn-secondary'>{toggle_label}</button></form></div></td></tr>"
                )
            rows = ''.join(row_items)
            heading = f"Редактирование квеста #{selected_id}" if selected_id else 'Новый квест'

            page = f"""
<main class='card admin-card'>
  <h1>🧩 Квесты и настройки</h1>
  <p class='muted'>Только интерфейс работы с квестами: создание, редактирование, этапы и пароли.</p>
  <div class='nav-links nav-inline'><a href='/admin'>← Назад</a></div>
  <h2>{heading}</h2>
  <form method='post' action='/admin/quest/save' class='admin-form'>
    <input type='hidden' name='id' value='{selected_id}'>
    <div class='tabs'><button type='button' class='tab-btn active' data-tab='tab-quest'>Квест</button><button type='button' class='tab-btn' data-tab='tab-steps'>Этапы</button><button type='button' class='tab-btn' data-tab='tab-list'>Список</button></div>
    <section id='tab-quest' class='tab-pane active'>
    <input name='title' placeholder='Название' maxlength='256' required value='{title}'>
    {'<input name=\'title_en\' placeholder=\'Название (EN)\' maxlength=\'256\' value=\''+title_en+'\'>' if show_english else ''}
    <input name='final_location' placeholder='Финальная локация' maxlength='512' value='{final_location}'>
    <input name='quest_time_limit_sec' type='number' min='0' placeholder='Ограничение времени (сек)' value='{time_limit}'>
    <label><input type='checkbox' name='active' {checked}> Активен</label>
    <button>Сохранить квест</button>
    </section>
  </form>
  <section id='tab-list' class='tab-pane'><h2>Список квестов</h2>
  <div class='table-wrap'><table><tr><th>ID</th><th>Название</th><th>Статус</th><th>Лимит</th><th>Действия</th></tr>{rows}</table></div></section>
  <section id='tab-steps' class='tab-pane'><h2>Этапы квеста</h2>
  {''.join([f"<form method='post' action='/admin/step/save' class='admin-form mobile-stack'><input type='hidden' name='quest_id' value='{selected_id}'><input type='hidden' name='step_id' value='{st['id']}'><input name='idx' type='number' min='1' value='{st['idx']}' required><textarea name='prompt' rows='3' placeholder='Загадка' required>{esc(st['prompt'])}</textarea><input name='password' placeholder='Пароль' value='{esc(st['password'])}' required><input name='step_time_limit_sec' type='number' min='0' placeholder='Лимит сек' value='{st['step_time_limit_sec'] or ''}'><button class='btn-secondary'>Сохранить этап #{st['idx']}</button></form>" for st in steps])}
  <form method='post' action='/admin/step/save' class='admin-form mobile-stack block'><input type='hidden' name='quest_id' value='{selected_id}'><input name='idx' type='number' min='1' placeholder='Номер этапа' required><textarea name='prompt' rows='3' placeholder='Новая загадка' required></textarea><input name='password' placeholder='Пароль/отгадка' required><input name='step_time_limit_sec' type='number' min='0' placeholder='Лимит сек'><button>Добавить этап</button></form>
</section></main>
<script>document.querySelectorAll('.tab-btn').forEach((btn)=>{{btn.addEventListener('click',()=>{{document.querySelectorAll('.tab-btn').forEach((b)=>b.classList.remove('active'));document.querySelectorAll('.tab-pane').forEach((p)=>p.classList.remove('active'));btn.classList.add('active');document.getElementById(btn.dataset.tab).classList.add('active');}});}});</script>
"""
            self.send_html(html(page))


        def save_admin_settings(self, data):
            enable_english = '1' if data.get('enable_english_content', [''])[-1] in ('on', '1', 'true') else '0'
            c = repo.connect()
            c.execute("INSERT INTO app_settings(key, value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ('enable_english_content', enable_english))
            c.commit(); c.close()
            self.audit('admin', 'admin.settings.updated', metadata={'enable_english_content': enable_english})
            self.send_response(303); self.send_header('Location', '/admin/settings'); self.end_headers()

        def save_quest_settings(self, data):
            quest_id = service.parse_int(data.get('id', [''])[0], minimum=1)
            title = service.sanitize_text(data.get('title', [''])[0], 256)
            title_en = service.sanitize_text(data.get('title_en', [''])[0], 256) if self.is_english_enabled() else ''
            final_location = service.sanitize_text(data.get('final_location', [''])[0], 512)
            quest_time_limit_sec = service.parse_int(data.get('quest_time_limit_sec', [''])[0], minimum=0)
            active = 1 if data.get('active', [''])[-1] in ('on', '1', 'true') else 0
            if not title:
                self.send_html(error_page(400, 'Некорректные данные', 'Название квеста обязательно'), 400); return
            c = repo.connect(); cur = c.cursor()
            if quest_id:
                cur.execute('UPDATE quests SET title=?, title_en=?, final_location=?, active=?, quest_time_limit_sec=? WHERE id=?', (title, title_en, final_location, active, quest_time_limit_sec, quest_id))
                action = 'admin.quest.updated'
            else:
                cur.execute('INSERT INTO quests(title,title_en,final_location,active,quest_time_limit_sec) VALUES (?,?,?,?,?)', (title, title_en, final_location, active, quest_time_limit_sec))
                quest_id = cur.lastrowid
                action = 'admin.quest.created'
            c.commit(); c.close()
            self.audit('admin', action, target=f'quest:{quest_id}', metadata={'quest_id': quest_id})
            self.send_response(303); self.send_header('Location', f'/admin/quest/edit?id={quest_id}'); self.end_headers()

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
            step_time_limit_sec = service.parse_int(data.get('step_time_limit_sec', [''])[0], minimum=0)
            if not quest_id or not idx or not prompt or not password:
                self.send_html(error_page(400, 'Некорректные данные', 'Заполните обязательные поля этапа'), 400); return
            c = repo.connect(); cur = c.cursor()
            if step_id:
                cur.execute('UPDATE steps SET idx=?, prompt=?, password=?, step_time_limit_sec=? WHERE id=? AND quest_id=?', (idx, prompt, password, step_time_limit_sec, step_id, quest_id))
            else:
                cur.execute('INSERT INTO steps(quest_id,idx,prompt,password,step_time_limit_sec) VALUES (?,?,?,?,?)', (quest_id, idx, prompt, password, step_time_limit_sec))
            c.commit(); c.close()
            self.audit('editor', 'editor.step.saved', target=f'quest:{quest_id}', metadata={'quest_id': quest_id, 'step_id': step_id, 'idx': idx})
            self.send_response(303); self.send_header('Location', f'/admin/quest/edit?id={quest_id}'); self.end_headers()

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
