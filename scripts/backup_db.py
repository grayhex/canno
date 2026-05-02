import argparse
import shutil
from datetime import datetime, timezone
from pathlib import Path

"""
Backup utility for SQLite database.

Operational baseline:
- Frequency: every 6 hours.
- Storage: local backups for 7 days + offsite copy for 30 days.
- Rotation: remove local files older than 7 days.
- Integrity: daily PRAGMA integrity_check and weekly test-restore.
"""


def main():
    parser = argparse.ArgumentParser(description='Backup SQLite database for Canno.')
    parser.add_argument('--db', default='canno.db', help='Path to source sqlite db')
    parser.add_argument('--out-dir', default='backups', help='Directory for backups')
    parser.add_argument('--retention-days', type=int, default=7, help='Delete local backups older than N days (default: 7)')
    args = parser.parse_args()

    src = Path(args.db)
    if not src.exists():
        raise SystemExit(f'Database not found: {src}')

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    dst = out_dir / f'{src.stem}_{ts}{src.suffix}'
    shutil.copy2(src, dst)
    for item in out_dir.glob(f'{src.stem}_*{src.suffix}'):
        if (datetime.now(timezone.utc).timestamp() - item.stat().st_mtime) > args.retention_days * 86400:
            item.unlink(missing_ok=True)
    print(dst)


if __name__ == '__main__':
    main()
