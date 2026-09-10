"""No-network, no-credentials scratch execution; never execute on the runner host."""
import os
from pathlib import Path
import resource
import struct
import subprocess
import tempfile


def base_sandbox():
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--size', '16777216', '--tmpfs', '/tmp',
            '--dir', '/home', '--dir', '/work']


def process_filter(language):
    # x86-64 seccomp: prevent subprocess/fork bombs; Node's runtime threads
    # are permitted, but non-thread clone/fork/vfork and clone3 are not.
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, 0xc000003e), (0x06, 0, 0, 0), (0x20, 0, 0, 0)]
    for syscall in (57, 58, 101, 165, 166, 250, 272, 298, 304, 308, 310, 311, 321, 323):
        instructions += [(0x15, 0, 1, syscall), (0x06, 0, 0, 0x50001)]
    instructions += [(0x15, 0, 1, 435), (0x06, 0, 0, 0x50026)]
    if language == 'python':
        instructions += [(0x15, 0, 1, 56), (0x06, 0, 0, 0x50001)]
    else:
        instructions += [(0x15, 0, 3, 56), (0x20, 0, 0, 16), (0x45, 1, 0, 0x10000), (0x06, 0, 0, 0x50001)]
    instructions += [(0x06, 0, 0, 0x7fff0000)]
    return b''.join(struct.pack('HBBI', *item) for item in instructions)


def run_probe(language, code, snapshot):
    if language not in ('python', 'javascript') or not isinstance(code, str) or len(code.encode()) > 32768:
        raise ValueError('probe language/code bound exceeded')
    with tempfile.TemporaryDirectory(prefix='mirrobot-probe-') as folder:
        root = Path(folder)
        script = root / ('probe.py' if language == 'python' else 'probe.mjs')
        script.write_text(code)
        command = base_sandbox() + ['--ro-bind', str(snapshot), '/repo', '--size', '16777216', '--tmpfs', '/work',
            '--ro-bind', str(script), '/work/' + script.name,
            '--chdir', '/work', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'HOME', '/home', '--setenv', 'LANG', 'C.UTF-8', '--',
            *(['python3', '-I', '/work/probe.py'] if language == 'python' else ['node', '/work/probe.mjs'])]
        def limits():
            resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
            resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        out = root / 'stdout'; err = root / 'stderr'
        seccomp = os.memfd_create('ryt-probe-filter', 0)
        os.write(seccomp, process_filter(language)); os.lseek(seccomp, 0, 0)
        command[1:1] = ['--seccomp', str(seccomp)]
        with out.open('wb') as stdout, err.open('wb') as stderr:
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                        timeout=20, env={'PATH': '/usr/bin:/bin'}, preexec_fn=limits, pass_fds=(seccomp,))
                status = result.returncode
            except subprocess.TimeoutExpired:
                status = 'timeout'
            finally:
                os.close(seccomp)
        return {'exit_code': status, 'stdout': out.read_bytes()[:64000].decode(errors='replace'),
                'stderr': err.read_bytes()[:64000].decode(errors='replace'),
                'scope': 'isolated scratch probe; no dependency install or production services'}
