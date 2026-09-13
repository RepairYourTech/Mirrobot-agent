"""The actual fork class must never append completion evidence for a failed chunk."""
import asyncio
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ryt.backend import ReviewBackend
from ryt.common import sha256
from ryt.providers import ProviderPool, routes


class FailedSessionContract(unittest.TestCase):
    def backend(self, root):
        backend = ReviewBackend.__new__(ReviewBackend)
        backend.root = root
        backend.data = root / 'data'; backend.data.mkdir()
        backend.binary = root / 'not-executed'
        backend.provider_pool = ProviderPool(routes({'OPENAI_KEY': 'SYNTHETIC-CREDENTIAL'}))
        backend.chunks = [[('a.ts', 'diff\n')], [('a.ts', 'diff\n')]]
        backend.deadline = time.monotonic() + 400
        backend.evidence = {'head': 'a'*40, 'base': 'b'*40, 'mirrobot_sessions': []}
        backend.inventory = {'files': {'a.ts': {}}, 'unavailable': []}
        backend.histories = []; backend.history_limited = False
        backend.reviewer = SimpleNamespace(
            git_provider=SimpleNamespace(pr=SimpleNamespace(title='Synthetic fixture', body='')),
            vars={}, token_handler=SimpleNamespace(count_tokens=len))
        return backend

    def result(self):
        return {'review': {'key_issues_to_review': []},
                'coverage': {'a.ts': {'sha256': sha256('diff\n'), 'lines': 1, 'delivered_lines': 1}}}, {'provider_requests': [{}], 'tool_events': []}

    def test_failed_predict_does_not_append_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = self.backend(Path(tmp))
            with patch('ryt.backend.execute_agent', side_effect=ValueError('synthetic failure')):
                with self.assertRaises(ValueError):
                    asyncio.run(backend.predict(0, backend.chunks[0]))
            self.assertEqual(backend.evidence['mirrobot_sessions'], [])
            self.assertEqual(len(backend.evidence['mirrobot_failures']), 1)

    def test_invalid_coverage_does_not_append_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = self.backend(Path(tmp)); result, telemetry = self.result()
            result['coverage']['a.ts']['delivered_lines'] = 0
            with patch('ryt.backend.execute_agent', return_value=(result, telemetry)):
                with self.assertRaisesRegex(ValueError, 'coverage manifest'):
                    asyncio.run(backend.predict(0, backend.chunks[0]))
            self.assertEqual(backend.evidence['mirrobot_sessions'], [])

    def test_failed_later_chunk_retains_only_prior_successful_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            backend = self.backend(Path(tmp))
            with patch('ryt.backend.execute_agent', return_value=self.result()):
                asyncio.run(backend.predict(0, backend.chunks[0]))
            self.assertEqual(backend.evidence['mirrobot_sessions'][0]['chunk_index'], 1)
            with patch('ryt.backend.execute_agent', side_effect=ValueError('synthetic later failure')):
                with self.assertRaises(ValueError):
                    asyncio.run(backend.predict(1, backend.chunks[1]))
            self.assertEqual(len(backend.evidence['mirrobot_sessions']), 1)
            self.assertEqual(backend.evidence['mirrobot_sessions'][0]['chunk_index'], 1)


if __name__ == '__main__': unittest.main()
