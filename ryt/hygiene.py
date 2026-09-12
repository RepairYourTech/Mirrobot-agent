"""Fail-closed lifecycle hygiene for persistent Mirrobot review hosts."""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time

LOCK = json.loads(Path(__file__).with_name('locks.json').read_text())
SESSION_PREFIX = 'review-'
# No valid review may outlive review_timeout_seconds. Keep an additional 30-minute
# margin for scheduler/cleanup overhead before a crashed directory becomes stale.
STALE_SECONDS = max(7200, int(LOCK['review_timeout_seconds']) + 1800)


def session_root():
    configured = os.environ.get('RYT_MIRROBOT_SESSION_ROOT')
    if configured:
        return Path(configured)
    runner_temp = os.environ.get('RUNNER_TEMP')
    if not runner_temp:
        raise RuntimeError('RUNNER_TEMP or RYT_MIRROBOT_SESSION_ROOT is required')
    return Path(runner_temp) / 'ryt-mirrobot-sessions'


def _safe_root(root):
    root = Path(root)
    if not root.is_absolute():
        raise RuntimeError('Mirrobot session root must be absolute')
    if root.is_symlink():
        raise RuntimeError('Mirrobot session root must not be a symlink')
    if not root.exists():
        if not root.parent.is_dir() or root.parent.is_symlink():
            raise RuntimeError('Mirrobot session root parent is unavailable or unsafe')
        root.mkdir(mode=0o700)
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        raise RuntimeError('Mirrobot session root must be an owned directory')
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise RuntimeError('Mirrobot session root must not grant group/other access')
    return root


def _session_entry(path):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f'unsafe Mirrobot session entry: {path.name}')
    if st.st_uid != os.geteuid():
        raise RuntimeError(f'foreign-owned Mirrobot session entry: {path.name}')
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise RuntimeError(f'permissive Mirrobot session entry: {path.name}')
    return st


def sweep_stale_sessions(root=None, *, max_age_seconds=STALE_SECONDS, now=None, dry_run=False):
    if type(max_age_seconds) not in (int, float) or max_age_seconds < LOCK['review_timeout_seconds'] + 60:
        raise ValueError('stale-session age must exceed the maximum live review timeout')
    root = _safe_root(session_root() if root is None else root)
    current = time.time() if now is None else now
    removed = []
    for child in sorted(root.iterdir()):
        if not child.name.startswith(SESSION_PREFIX):
            continue
        st = _session_entry(child)
        if current - st.st_mtime < max_age_seconds:
            continue
        removed.append(child.name)
        if dry_run:
            continue
        shutil.rmtree(child)
        if child.exists() or child.is_symlink():
            raise RuntimeError(f'failed to remove stale Mirrobot session: {child.name}')
    return removed


def create_session_directory(root=None):
    root = _safe_root(session_root() if root is None else root)
    sweep_stale_sessions(root)
    temporary = tempfile.TemporaryDirectory(prefix=SESSION_PREFIX, dir=root)
    path = Path(temporary.name)
    path.chmod(0o700)
    _session_entry(path)
    return temporary, path


def secure_active_session(path):
    path = Path(path)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        raise RuntimeError('active Mirrobot session path is unsafe')
    path.chmod(0o700)
    _session_entry(path)
    return path


def touch_session(path):
    path = secure_active_session(path)
    os.utime(path, None)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Sweep stale Mirrobot review sessions from a persistent runner.')
    parser.add_argument('--root', type=Path)
    parser.add_argument('--max-age-seconds', type=int, default=STALE_SECONDS)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    removed = sweep_stale_sessions(args.root, max_age_seconds=args.max_age_seconds, dry_run=args.dry_run)
    for name in removed:
        print(('would-remove ' if args.dry_run else 'removed ') + name)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
