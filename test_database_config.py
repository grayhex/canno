import importlib
import os
import tempfile
import unittest

from canno.repositories.db import QuestRepository, SqliteRepository


class DatabaseConfigTestCase(unittest.TestCase):
    def test_empty_database_url_falls_back_to_sqlite_db_path(self):
        old = dict(os.environ)
        try:
            os.environ['CANNO_DATABASE_URL'] = ''
            os.environ['CANNO_DB_ENGINE'] = 'sqlite'
            os.environ['CANNO_DB_PATH'] = '/data/canno.db'
            from canno import config

            reloaded = importlib.reload(config)
            self.assertEqual(reloaded.CANNO_DATABASE_URL, 'sqlite:////data/canno.db')
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_docker_sqlite_url_resolves_to_expected_path(self):
        repo = SqliteRepository('sqlite:////data/canno.db')
        self.assertEqual(repo._resolve_path(), '/data/canno.db')

    def test_migrations_and_seed_use_same_configured_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = os.path.join(tmp, 'canno.db')
            repo = SqliteRepository(f'sqlite:///{db_path}')
            quest_repo = QuestRepository(repo)

            quest_repo.apply_migrations('2026-05-02T00:00:00')
            quest_repo.seed_demo('2026-05-02T00:00:00', 'tok123')

            conn = repo.connect()
            try:
                quests = conn.execute('SELECT COUNT(*) AS c FROM quests').fetchone()['c']
                participants = conn.execute('SELECT COUNT(*) AS c FROM participants').fetchone()['c']
            finally:
                conn.close()

            self.assertGreaterEqual(quests, 1)
            self.assertGreaterEqual(participants, 1)
            self.assertTrue(os.path.exists(db_path))


if __name__ == '__main__':
    unittest.main()
