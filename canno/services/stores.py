from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class SessionRecord:
    session_id: str
    expires_at: datetime


class SessionStore:
    def get(self, session_id: str):
        raise NotImplementedError

    def set(self, session_id: str, expires_at: datetime):
        raise NotImplementedError

    def delete(self, session_id: str):
        raise NotImplementedError

    def cleanup_expired(self, now_dt: datetime):
        raise NotImplementedError


class AttemptLimiterStore:
    def get_attempts_since(self, bucket: str, key: str, cutoff: datetime):
        raise NotImplementedError

    def add_attempt(self, bucket: str, key: str, at: datetime):
        raise NotImplementedError

    def clear_attempts(self, bucket: str, key: str):
        raise NotImplementedError

    def cleanup_expired(self, cutoff: datetime):
        raise NotImplementedError


class SqliteAuthStore(SessionStore, AttemptLimiterStore):
    def __init__(self, repo, cleanup_interval_seconds: int = 60):
        self.repo = repo
        self.cleanup_interval = timedelta(seconds=cleanup_interval_seconds)
        self._last_cleanup = None

    def ensure_schema(self):
        c = self.repo.connect()
        cur = c.cursor()
        cur.executescript(
            '''
CREATE TABLE IF NOT EXISTS admin_sessions (
  session_id TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bucket TEXT NOT NULL,
  key TEXT NOT NULL,
  attempted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_bucket_key_time ON auth_attempts(bucket, key, attempted_at);
'''
        )
        c.commit()
        c.close()

    def _maybe_cleanup(self, now_dt: datetime):
        if self._last_cleanup and now_dt - self._last_cleanup < self.cleanup_interval:
            return
        self.cleanup_expired(now_dt - timedelta(days=1))
        self.cleanup_sessions(now_dt)
        self._last_cleanup = now_dt

    def get(self, session_id: str):
        c = self.repo.connect()
        row = c.execute('SELECT expires_at FROM admin_sessions WHERE session_id=?', (session_id,)).fetchone()
        c.close()
        return datetime.fromisoformat(row['expires_at']) if row else None

    def set(self, session_id: str, expires_at: datetime):
        self._maybe_cleanup(expires_at)
        c = self.repo.connect()
        c.execute('INSERT INTO admin_sessions(session_id, expires_at) VALUES(?,?) ON CONFLICT(session_id) DO UPDATE SET expires_at=excluded.expires_at', (session_id, expires_at.isoformat()))
        c.commit(); c.close()

    def delete(self, session_id: str):
        c = self.repo.connect(); c.execute('DELETE FROM admin_sessions WHERE session_id=?', (session_id,)); c.commit(); c.close()

    def cleanup_sessions(self, now_dt: datetime):
        c = self.repo.connect(); c.execute('DELETE FROM admin_sessions WHERE expires_at<=?', (now_dt.isoformat(),)); c.commit(); c.close()

    def cleanup_expired(self, cutoff: datetime):
        c = self.repo.connect(); c.execute('DELETE FROM auth_attempts WHERE attempted_at<=?', (cutoff.isoformat(),)); c.commit(); c.close()

    def get_attempts_since(self, bucket: str, key: str, cutoff: datetime):
        self._maybe_cleanup(cutoff)
        c = self.repo.connect()
        row = c.execute('SELECT COUNT(*) c FROM auth_attempts WHERE bucket=? AND key=? AND attempted_at>?', (bucket, key, cutoff.isoformat())).fetchone()
        c.close()
        return row['c']

    def add_attempt(self, bucket: str, key: str, at: datetime):
        self._maybe_cleanup(at)
        c = self.repo.connect(); c.execute('INSERT INTO auth_attempts(bucket,key,attempted_at) VALUES(?,?,?)', (bucket, key, at.isoformat())); c.commit(); c.close()

    def clear_attempts(self, bucket: str, key: str):
        c = self.repo.connect(); c.execute('DELETE FROM auth_attempts WHERE bucket=? AND key=?', (bucket, key)); c.commit(); c.close()
