import json
import secrets
import sqlite3
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import parse_qs, urlparse
from http.server import BaseHTTPRequestHandler, HTTPServer

DB = 'canno.db'
TZ = ZoneInfo('Europe/Moscow')


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    c = db(); cur=c.cursor()
    cur.executescript('''
CREATE TABLE IF NOT EXISTS quests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  final_location TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  quest_time_limit_sec INTEGER
);
CREATE TABLE IF NOT EXISTS steps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quest_id INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  prompt TEXT NOT NULL,
  password TEXT NOT NULL,
  step_time_limit_sec INTEGER,
  FOREIGN KEY(quest_id) REFERENCES quests(id)
);
CREATE TABLE IF NOT EXISTS participants (
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
CREATE TABLE IF NOT EXISTS attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  participant_id INTEGER NOT NULL,
  step_idx INTEGER NOT NULL,
  entered_password TEXT NOT NULL,
  success INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(participant_id) REFERENCES participants(id)
);
''')
    c.commit()
    q = cur.execute('SELECT COUNT(*) c FROM quests').fetchone()['c']
    if q == 0:
        cur.execute('INSERT INTO quests(title, final_location, active, quest_time_limit_sec) VALUES (?,?,?,?)',
                    ('Демо-квест', 'Под стойкой у окна', 1, 3600))
        quest_id = cur.lastrowid
        steps = [
            (quest_id,1,'Найди бумажку возле входной двери и введи слово.', 'СОЛНЦЕ', 600),
            (quest_id,2,'Ищи под столом в переговорной.', 'ЛИСТ', 600),
            (quest_id,3,'Проверь полку с книгами.', 'МАЯК', 600),
            (quest_id,4,'Открой ящик с канцелярией.', 'КЛЮЧ', 600),
        ]
        cur.executemany('INSERT INTO steps(quest_id,idx,prompt,password,step_time_limit_sec) VALUES (?,?,?,?,?)', steps)
        token = secrets.token_urlsafe(8)
        cur.execute('INSERT INTO participants(quest_id, token, started_at, step_started_at) VALUES (?,?,?,?)',
                    (quest_id, token, now(), now()))
        c.commit()
        print(f'Demo player URL: http://localhost:8000/play/{token}')
    c.close()


def now():
    return datetime.now(TZ).isoformat()


def next_day_start_iso():
    n = datetime.now(TZ)
    t = (n + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return t.isoformat()


def html(body):
    return f"""<!doctype html><html lang='ru'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Canno Quest</title><link rel='stylesheet' href='/static.css'></head><body>{body}</body></html>"""


class H(BaseHTTPRequestHandler):
    def send_html(self, text, status=200):
        self.send_response(status); self.send_header('Content-Type','text/html; charset=utf-8'); self.end_headers(); self.wfile.write(text.encode())

    def send_json(self, data, status=200):
        self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.end_headers(); self.wfile.write(json.dumps(data, ensure_ascii=False).encode())

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == '/':
            self.send_html(html("<main class='card'><h1>Canno Quest</h1><p>Открой ссылку участника /play/&lt;token&gt; или админку /admin</p></main>")); return
        if p.path == '/static.css':
            css=open('static.css').read(); self.send_response(200); self.send_header('Content-Type','text/css'); self.end_headers(); self.wfile.write(css.encode()); return
        if p.path.startswith('/play/'):
            token=p.path.split('/play/')[1]
            self.render_play(token); return
        if p.path == '/admin':
            self.render_admin(); return
        self.send_html(html('<main class="card"><h1>404</h1></main>'),404)

    def do_POST(self):
        p = urlparse(self.path)
        length = int(self.headers.get('Content-Length',0)); data=parse_qs(self.rfile.read(length).decode())
        if p.path.startswith('/play/'):
            token=p.path.split('/play/')[1]
            self.submit_password(token, data.get('password',[''])[0]); return
        if p.path == '/admin/create-participant':
            quest_id=int(data.get('quest_id',['1'])[0]); token=secrets.token_urlsafe(8)
            c=db(); c.execute('INSERT INTO participants(quest_id,token,started_at,step_started_at) VALUES (?,?,?,?)',(quest_id,token,now(),now())); c.commit(); c.close()
            self.send_html(html(f"<main class='card'><p>Ссылка: <a href='/play/{token}'>/play/{token}</a></p><a href='/admin'>Назад</a></main>")); return
        self.send_json({'error':'not found'},404)

    def render_play(self, token):
        c=db(); cur=c.cursor()
        p=cur.execute('SELECT * FROM participants WHERE token=?',(token,)).fetchone()
        if not p: self.send_html(html("<main class='card'><h2>Ссылка недействительна</h2></main>"),404); return
        q=cur.execute('SELECT * FROM quests WHERE id=?',(p['quest_id'],)).fetchone()
        steps=cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx',(p['quest_id'],)).fetchall()
        if not q['active']: self.send_html(html("<main class='card'><h2>Квест закрыт админом</h2></main>")); return
        if p['locked_until'] and datetime.fromisoformat(p['locked_until'])>datetime.now(TZ):
            self.send_html(html(f"<main class='card'><h2>До завтра недоступно</h2><p>Возвращайтесь после: {p['locked_until']}</p></main>")); return
        if p['completed']:
            self.send_html(html(f"<main class='card'><h2>Финиш!</h2><p>Приз находится: <b>{q['final_location']}</b></p></main>")); return
        step=next((s for s in steps if s['idx']==p['current_step']),None)
        progress=int((p['current_step']-1)/len(steps)*100)
        self.send_html(html(f"""<main class='card'><h1>{q['title']}</h1><div class='bar'><span style='width:{progress}%'></span></div><p>Этап {p['current_step']} из {len(steps)}</p><p>{step['prompt']}</p><form method='post'><input name='password' placeholder='Введите пароль' required><button>Проверить</button></form><p><a href='/admin'>Админка</a></p></main>"""))

    def submit_password(self, token, password):
        c=db(); cur=c.cursor(); p=cur.execute('SELECT * FROM participants WHERE token=?',(token,)).fetchone()
        if not p: self.send_html('bad',404); return
        steps=cur.execute('SELECT * FROM steps WHERE quest_id=? ORDER BY idx',(p['quest_id'],)).fetchall()
        q=cur.execute('SELECT * FROM quests WHERE id=?',(p['quest_id'],)).fetchone()
        step=next((s for s in steps if s['idx']==p['current_step']),None)
        # timers
        n=datetime.now(TZ)
        if q['quest_time_limit_sec'] and p['started_at']:
            if n > datetime.fromisoformat(p['started_at']) + timedelta(seconds=q['quest_time_limit_sec']):
                cur.execute('UPDATE participants SET locked_until=? WHERE id=?',(next_day_start_iso(),p['id'])); c.commit(); self.send_html(html("<main class='card'><p>Время квеста вышло. До завтра.</p></main>")); return
        if step['step_time_limit_sec'] and p['step_started_at']:
            if n > datetime.fromisoformat(p['step_started_at']) + timedelta(seconds=step['step_time_limit_sec']):
                cur.execute('UPDATE participants SET locked_until=? WHERE id=?',(next_day_start_iso(),p['id'])); c.commit(); self.send_html(html("<main class='card'><p>Время этапа вышло. До завтра.</p></main>")); return
        success = int(password == step['password'])
        cur.execute('INSERT INTO attempts(participant_id,step_idx,entered_password,success,created_at) VALUES (?,?,?,?,?)',(p['id'],p['current_step'],password,success,now()))
        if success:
            if p['current_step'] >= len(steps):
                cur.execute('UPDATE participants SET completed=1 WHERE id=?',(p['id'],))
            else:
                cur.execute('UPDATE participants SET current_step=current_step+1, step_started_at=? WHERE id=?',(now(),p['id']))
            c.commit(); self.send_response(303); self.send_header('Location',f'/play/{token}'); self.end_headers(); return
        c.commit(); self.send_html(html(f"<main class='card'><p>Неверный пароль</p><a href='/play/{token}'>Назад</a></main>"))

    def render_admin(self):
        c=db(); cur=c.cursor(); quests=cur.execute('SELECT * FROM quests').fetchall(); parts=cur.execute('SELECT * FROM participants ORDER BY id DESC').fetchall()
        qopts=''.join([f"<option value='{q['id']}'>{q['title']}</option>" for q in quests])
        rows=''.join([f"<tr><td>{p['id']}</td><td><a href='/play/{p['token']}'>{p['token']}</a></td><td>{p['current_step']}</td><td>{'да' if p['completed'] else 'нет'}</td><td>{p['locked_until'] or '-'}</td></tr>" for p in parts])
        self.send_html(html(f"<main class='card'><h1>Админка</h1><form method='post' action='/admin/create-participant'><select name='quest_id'>{qopts}</select><button>Сгенерировать ссылку участника</button></form><h2>Участники</h2><table><tr><th>ID</th><th>Token</th><th>Этап</th><th>Финиш</th><th>Блок до</th></tr>{rows}</table></main>"))

if __name__ == '__main__':
    init_db()
    HTTPServer(('0.0.0.0', 8000), H).serve_forever()
