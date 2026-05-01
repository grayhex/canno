import os
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer

os.environ.setdefault('CANNO_ADMIN_PASSWORD', 'test-admin-password')
_test_tmpdir = tempfile.TemporaryDirectory()
os.environ['CANNO_DATABASE_URL'] = f"sqlite:///{os.path.join(_test_tmpdir.name, 'test.db')}"

import app
from canno.http.handlers import create_handler
from canno.services.stores import SqliteAuthStore


class CannoTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.init_db()
        app.AUTH_STORE.ensure_schema()

        cls.server = HTTPServer(('127.0.0.1', 0), app.H)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)
        cls.server.server_close()
        _test_tmpdir.cleanup()

    def request(self, method, path, body=None, headers=None, port=None):
        conn = HTTPConnection('127.0.0.1', port or self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read().decode('utf-8', errors='ignore')
        hdrs = dict(resp.getheaders())
        status = resp.status
        conn.close()
        return status, hdrs, data

    def test_timer_and_parse_helpers(self):
        self.assertEqual(app.parse_int('42', minimum=1), 42)
        self.assertIsNone(app.parse_int('abc', minimum=1))
        self.assertEqual(app.sanitize_text('  hello  ', 5), 'hello')
        iso = app.next_day_start_iso()
        self.assertIn('T00:00:00', iso)

    def test_play_endpoint_and_wrong_password(self):
        c = app.db()
        token = c.execute('SELECT token FROM participants ORDER BY id LIMIT 1').fetchone()['token']
        c.close()

        status, _, body = self.request('GET', f'/play/{token}')
        self.assertEqual(status, 200)
        self.assertIn('Этап', body)

        payload = 'password=WRONG'
        status, _, body = self.request(
            'POST',
            f'/play/{token}',
            body=payload,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        self.assertEqual(status, 200)
        self.assertIn('Неверный пароль', body)

    def test_admin_login_and_persisted_session_after_restart(self):
        payload = 'username=admin&password=test-admin-password'
        status, headers, _ = self.request(
            'POST', '/admin/login', body=payload, headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        self.assertEqual(status, 303)
        cookie = headers['Set-Cookie'].split(';', 1)[0]

        status, _, body = self.request('GET', '/admin', headers={'Cookie': cookie})
        self.assertEqual(status, 200)
        self.assertIn('Админка', body)

        # simulate restart: new handler + auth store reads same DB
        restarted_store = SqliteAuthStore(app.repo)
        restarted_store.ensure_schema()
        restarted_handler = create_handler(app.repo, app.service, app.ADMIN_PASSWORD_HASH_VALUE, restarted_store)
        srv = HTTPServer(('127.0.0.1', 0), restarted_handler)
        port = srv.server_port
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        time.sleep(0.05)
        try:
            status, _, body = self.request('GET', '/admin', headers={'Cookie': cookie}, port=port)
            self.assertEqual(status, 200)
            self.assertIn('Админка', body)
        finally:
            srv.shutdown(); th.join(timeout=2); srv.server_close()

    def test_step_limit_persists_after_restart(self):
        c = app.db()
        token = c.execute('SELECT token FROM participants ORDER BY id LIMIT 1').fetchone()['token']
        c.close()

        for _ in range(app.config.MAX_STEP_ATTEMPTS):
            self.request(
                'POST', f'/play/{token}', body='password=WRONG', headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

        restarted_store = SqliteAuthStore(app.repo)
        restarted_store.ensure_schema()
        restarted_handler = create_handler(app.repo, app.service, app.ADMIN_PASSWORD_HASH_VALUE, restarted_store)
        srv = HTTPServer(('127.0.0.1', 0), restarted_handler)
        port = srv.server_port
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start(); time.sleep(0.05)
        try:
            status, _, body = self.request(
                'POST', f'/play/{token}', body='password=WRONG', headers={'Content-Type': 'application/x-www-form-urlencoded'}, port=port
            )
            self.assertEqual(status, 429)
            self.assertIn('Слишком много попыток', body)
        finally:
            srv.shutdown(); th.join(timeout=2); srv.server_close()


if __name__ == '__main__':
    unittest.main()
