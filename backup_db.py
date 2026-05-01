import argparse
import shutil
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Backup SQLite database for Canno.')
    parser.add_argument('--db', default='canno.db', help='Path to source sqlite db')
    parser.add_argument('--out-dir', default='backups', help='Directory for backups')
    args = parser.parse_args()

    src = Path(args.db)
    if not src.exists():
        raise SystemExit(f'Database not found: {src}')

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    dst = out_dir / f'{src.stem}_{ts}{src.suffix}'
    shutil.copy2(src, dst)
    print(dst)


if __name__ == '__main__':
    main()
