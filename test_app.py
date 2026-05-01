import os
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import HTTPServer

os.environ.setdefault('CANNO_ADMIN_PASSWORD', 'test-admin-password')

import app


class CannoTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls._old_db = app.DB
        app.DB = os.path.join(cls._tmpdir.name, 'test.db')
        app.LOGIN_ATTEMPTS.clear()
        app.STEP_ATTEMPTS.clear()
        app.SESSIONS.clear()
        app.init_db()

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
        app.DB = cls._old_db
        cls._tmpdir.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = HTTPConnection('127.0.0.1', self.port, timeout=5)
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

    def test_admin_login_and_redirect(self):
        status, _, _ = self.request('GET', '/admin')
        self.assertEqual(status, 303)

        payload = 'username=admin&password=test-admin-password'
        status, headers, _ = self.request(
            'POST',
            '/admin/login',
            body=payload,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        self.assertEqual(status, 303)
        self.assertIn('Set-Cookie', headers)


if __name__ == '__main__':
    unittest.main()
