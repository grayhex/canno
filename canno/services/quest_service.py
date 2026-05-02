import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta

from canno import config


logger = logging.getLogger('canno')


class QuestService:
    def __init__(self):
        self.login_attempts = {}
        self.step_attempts = {}
        self.sessions = {}

    def now_dt(self):
        return datetime.now(config.TZ)

    def now(self):
        return self.now_dt().isoformat()

    def next_day_start_iso(self):
        n = self.now_dt()
        t = (n + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return t.isoformat()

    def sanitize_text(self, raw, max_len=256):
        if raw is None:
            return ""
        return str(raw).strip()[:max_len]

    def parse_int(self, raw, default=None, minimum=None):
        raw = self.sanitize_text(raw, 32)
        if raw == '':
            return default
        if not raw.isdigit():
            return None
        value = int(raw)
        if minimum is not None and value < minimum:
            return None
        return value

    def init_admin_password_hash(self):
        if config.ADMIN_PASSWORD_HASH:
            return config.ADMIN_PASSWORD_HASH
        if not config.ADMIN_PASSWORD:
            raise RuntimeError('Set CANNO_ADMIN_PASSWORD_HASH or CANNO_ADMIN_PASSWORD')
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac('sha256', config.ADMIN_PASSWORD.encode(), salt.encode(), 200_000).hex()
        return f'pbkdf2_sha256$200000${salt}${digest}'

    def resolve_password_hash(self, password_hash, raw_password):
        if password_hash:
            return password_hash
        if not raw_password:
            return ''
        return self.hash_password(raw_password)

    def verify_password(self, raw_password, stored_hash):
        try:
            algo, iterations, salt, digest = stored_hash.split('$', 3)
            if algo != 'pbkdf2_sha256':
                return False
            candidate = hashlib.pbkdf2_hmac('sha256', raw_password.encode(), salt.encode(), int(iterations)).hex()
            return hmac.compare_digest(candidate, digest)
        except Exception:
            logger.error('Invalid password hash format')
            return False

    def hash_password(self, raw_password):
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac('sha256', raw_password.encode(), salt.encode(), 200_000).hex()
        return f'pbkdf2_sha256$200000${salt}${digest}'

    def blocked(self, storage, key, max_attempts, window_seconds):
        attempts = storage.get(key, [])
        cutoff = self.now_dt() - timedelta(seconds=window_seconds)
        attempts = [ts for ts in attempts if ts > cutoff]
        storage[key] = attempts
        return len(attempts) >= max_attempts

    def record_attempt(self, storage, key, window_seconds):
        attempts = storage.setdefault(key, [])
        cutoff = self.now_dt() - timedelta(seconds=window_seconds)
        attempts[:] = [ts for ts in attempts if ts > cutoff]
        attempts.append(self.now_dt())
