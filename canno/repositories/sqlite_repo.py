import sqlite3


class SqliteRepository:
    def __init__(self, db_path_getter):
        self._db_path_getter = db_path_getter

    def connect(self):
        conn = sqlite3.connect(self._db_path_getter())
        conn.row_factory = sqlite3.Row
        return conn
