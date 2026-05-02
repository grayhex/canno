import os
import tempfile
import unittest
from pathlib import Path

from canno.repositories.db import create_repository


class SqlitePathParsingTests(unittest.TestCase):
    def test_direct_relative_path_creates_db_in_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            prev = os.getcwd()
            os.chdir(tmp)
            try:
                repo = create_repository('ci_backup_test.db')
                conn = repo.connect()
                conn.execute('CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY)')
                conn.commit()
                conn.close()
                self.assertTrue(Path('ci_backup_test.db').exists())
            finally:
                os.chdir(prev)

    def test_sqlite_absolute_path_url_creates_db_at_absolute_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            abs_path = Path(tmp) / 'data' / 'canno.db'
            repo = create_repository(f'sqlite:///{abs_path}')
            conn = repo.connect()
            conn.execute('CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY)')
            conn.commit()
            conn.close()
            self.assertTrue(abs_path.exists())


if __name__ == '__main__':
    unittest.main()
