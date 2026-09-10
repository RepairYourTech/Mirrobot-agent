"""Small strict serialization and untrusted-path boundaries (stdlib only)."""
import hashlib
import json
from pathlib import Path, PurePosixPath


def sha256(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def load_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON constant')))


def relative_path(value):
    if (not isinstance(value, str) or not value or len(value) > 4096 or
            '\\' in value or any(ord(c) < 32 for c in value)):
        raise ValueError('invalid repository path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('unsafe repository path')
    return path


def confined(root, name):
    path = root.joinpath(*relative_path(name).parts)
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError('repository path escaped snapshot')
    if any(part.is_symlink() for part in [path, *path.parents] if part != root.parent):
        raise ValueError('symlink not allowed')
    return resolved


def write_json(path, data):
    text = json.dumps(data, sort_keys=True, ensure_ascii=True, allow_nan=False)
    temporary = path.with_suffix('.pending')
    temporary.write_text(text)
    temporary.chmod(0o600)
    temporary.replace(path)


def read_text(path, limit=2 * 1024 * 1024):
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError('missing or oversized text file')
    data = path.read_bytes()
    if b'\0' in data:
        raise ValueError('binary file is not a text input')
    return data.decode('utf-8')
