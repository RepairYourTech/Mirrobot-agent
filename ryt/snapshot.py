"""Safe, bounded extraction of exact-commit repository snapshots as inert data."""
import io
import tarfile
from pathlib import Path
from ryt.common import relative_path, sha256, write_json

MAX_ARCHIVE = 192 * 1024 * 1024
MAX_EXPANDED = 768 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_FILES = 100000


def extract_snapshot(data, destination):
    if len(data) > MAX_ARCHIVE or destination.exists():
        raise ValueError('snapshot size/destination refused')
    destination.mkdir(mode=0o700)
    files, unavailable, total = {}, [], 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        prefix = None
        for index, member in enumerate(archive):
            if index >= MAX_FILES:
                raise ValueError('snapshot member bound exceeded')
            full = relative_path(member.name.rstrip('/'))
            if prefix is None:
                prefix = full.parts[0]
            if full.parts[0] != prefix:
                raise ValueError('multiple snapshot roots')
            if len(full.parts) == 1:
                continue
            name = '/'.join(full.parts[1:])
            if member.isdir():
                continue
            total += member.size
            if total > MAX_EXPANDED:
                raise ValueError('snapshot expansion bound exceeded')
            if name in files:
                raise ValueError('duplicate snapshot file')
            if (not member.isfile() or member.size > MAX_FILE or
                    '.git' in full.parts):
                unavailable.append({'path': name, 'reason': 'nonregular, oversized or prohibited metadata'})
                continue
            content = archive.extractfile(member).read(MAX_FILE + 1)
            if len(content) != member.size:
                raise ValueError('snapshot member length mismatch')
            path = destination.joinpath(*full.parts[1:])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o400)
            files[name] = {'bytes': len(content), 'sha256': sha256(content)}
    return {'files': files, 'unavailable': unavailable, 'archive_sha256': sha256(data)}
