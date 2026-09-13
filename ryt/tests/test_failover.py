"""Fresh-session, complete-input and aggregate-budget failover tests."""
import json
from pathlib import Path
import tempfile
import unittest

from ryt.common import write_json
from ryt.failover import execute_with_pool
from ryt.providers import ProviderPool, routes


class FailoverExecution(unittest.TestCase):
    def test_rate_limit_restarts_in_fresh_session_with_same_snapshot_and_remaining_budget(self):
        pool = ProviderPool(routes({'OPENAI_KEY': 'glm', 'PR_REVIEW_BAI_01': 'bai1', 'PR_REVIEW_BAI_02': 'bai2'}))
        calls = []
        def execute(binary, data, session, key, count_tokens, policy, timeout_seconds, **options):
            calls.append((session, key, options))
            self.assertEqual(data, Path('/same-snapshot'))
            self.assertEqual(policy, 'trusted-policy')
            if key == 'glm':
                write_json(session / 'progress.json', {'failure_code': 'HTTP_429',
                    'provider_requests': [{'model': 'glm-5.3-flash'}], 'tool_events': [{}]})
                raise ValueError('arbitrary text must not enter evidence')
            return {'complete': True}, {'provider_requests': [{'model': 'qwen3.8-flash'}], 'tool_events': [{}]}
        with tempfile.TemporaryDirectory() as temp:
            result, telemetry = execute_with_pool(execute, Path('/binary'), Path('/same-snapshot'),
                Path(temp), pool, len, 'trusted-policy', 60)
        self.assertTrue(result['complete'])
        self.assertNotEqual(calls[0][0], calls[1][0])
        self.assertEqual(calls[0][2], {'profile_id': 'zai', 'max_calls': 64, 'max_tools': 384})
        self.assertEqual(calls[1][2], {'profile_id': 'bai-qwen', 'max_calls': 63, 'max_tools': 383})
        self.assertEqual(telemetry['route'], 'bai-01')
        self.assertEqual([a['status'] for a in telemetry['attempts']], ['failed', 'complete'])
        self.assertNotIn('arbitrary', json.dumps(telemetry))
        self.assertEqual(pool.next().alias, 'bai-01')
        self.assertEqual(telemetry['pool_tool_count'], 2)

    def test_assurance_failure_is_not_hidden_by_trying_another_model(self):
        pool = ProviderPool(routes({'OPENAI_KEY': 'glm', 'PR_REVIEW_BAI_01': 'bai'}))
        seen = []
        def execute(binary, data, session, *args, **kwargs):
            seen.append(session)
            write_json(session / 'progress.json', {'failure_code': 'finish_length', 'provider_requests': [{}]})
            raise ValueError('truncated response')
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            execute_with_pool(execute, None, None, Path(temp), pool, len, '', 60)
        self.assertEqual(len(seen), 1)

    def test_full_call_budget_cannot_be_reset_by_changing_credentials(self):
        pool = ProviderPool(routes({'OPENAI_KEY': 'glm', 'PR_REVIEW_BAI_01': 'bai'}))
        seen = []
        def execute(binary, data, session, *args, **kwargs):
            seen.append(session)
            write_json(session / 'progress.json', {'failure_code': 'HTTP_429', 'provider_requests': [{}] * 64})
            raise ValueError('unavailable')
        with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(ValueError, 'budget'):
            execute_with_pool(execute, None, None, Path(temp), pool, len, '', 60)
        self.assertEqual(len(seen), 1)

    def test_full_tool_budget_cannot_be_reset_by_changing_credentials(self):
        pool = ProviderPool(routes({'OPENAI_KEY': 'glm', 'PR_REVIEW_BAI_01': 'bai'}))
        seen = []
        def execute(binary, data, session, *args, **kwargs):
            seen.append(session)
            write_json(session / 'progress.json', {'failure_code': 'HTTP_429',
                'provider_requests': [{}], 'tool_events': [{}] * 384})
            raise ValueError('unavailable')
        with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(ValueError, 'budget'):
            execute_with_pool(execute, None, None, Path(temp), pool, len, '', 60)
        self.assertEqual(len(seen), 1)


if __name__ == '__main__':
    unittest.main()
