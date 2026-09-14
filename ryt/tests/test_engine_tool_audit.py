"""An engine rejection is different from executing a forbidden tool."""
import unittest

from ryt.backend import audit_engine_tools
from ryt.diagnostics import SessionFailure


class EngineToolAudit(unittest.TestCase):
    def test_unexpected_execution_and_arbitrary_errors_still_fail(self):
        for tool, status, error in [
            ('bash', 'completed', ''),
            ('bash', 'error', 'permission denied'),
            ('ryt_unregistered', 'completed', ''),
            ('not_a_registered_tool', 'completed',
             "Model tried to call unavailable tool 'invalid'. Available tools: ryt_submit_review."),
            ('not_a_registered_tool', 'error',
             "Model tried to call unavailable tool 'invalid'. Available tools: bash, ryt_submit_review."),
        ]:
            with self.subTest(tool=tool, status=status), self.assertRaises(SessionFailure):
                audit_engine_tools([{'type': 'tool_use', 'part': {
                    'tool': tool, 'state': {'status': status, 'error': error}}}])

    def test_declared_tool_events_remain_valid(self):
        self.assertEqual(audit_engine_tools([{'type': 'tool_use', 'part': {
            'tool': 'ryt_read_file', 'state': {'status': 'error', 'error': 'missing file'}}}]), 0)


if __name__ == '__main__':
    unittest.main()
